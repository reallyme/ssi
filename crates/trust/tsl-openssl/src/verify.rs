// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use envelopes_x509::X509Certificate;
use identity_trust_tsl_core::{TrustedList, TslMediaType, TslPointer};

use crate::error::TslOpenSslError;
#[cfg(all(feature = "native", feature = "xmlsec-ffi"))]
use crate::error::TslSignatureProfileFailureReason;
#[cfg(feature = "native")]
use crate::error::TslTrustRootErrorReason;
#[cfg(feature = "native")]
use crate::signer_profile::validate_tlso_signer_profile;
use crate::signer_profile::{TslSignatureAlgorithm, TslSignerProfileEvidence};
#[cfg(feature = "native")]
use crate::trust_roots::validate_trust_root_budget;

mod signer_policy;
#[cfg(feature = "native")]
mod trust_error;
#[cfg(feature = "native")]
mod xmlsec_backend;
use signer_policy::bind_tsl_signer_policy;
#[cfg(feature = "native")]
use trust_error::map_trust_failure;
#[cfg(feature = "native")]
use xmlsec_backend::verify_tsl_xmldsig;

/// Atomic result of TSL XMLDSig verification and signer trust evaluation.
pub struct VerifiedTrustedList {
    /// Bounded normalized TS 119 612 projection.
    list: TrustedList,
    /// Three-state signer decision and its source/anchor/status evidence.
    signer_trust: reallyme_trust_core::TrustDecision,
    /// SHA-256 identity of the certificate whose key verified `SignatureValue`.
    signer_certificate_sha256: [u8; 32],
    /// SHA-256 identities of the bounded certificates in the verified `KeyInfo`.
    key_info_certificate_sha256: Vec<[u8; 32]>,
    /// Typed evidence identifying the signer-authorization policy that passed.
    signer_authorization: TslSignerAuthorizationEvidence,
    /// Authenticated XML signature suite bound to the TLSO certified key.
    signature_algorithm: TslSignatureAlgorithm,
}

#[path = "verify/verified_list.rs"]
mod verified_list;

/// Authenticated policy used to authorize the XML signature certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TslSignerAuthorizationEvidence {
    /// The signer satisfied the TS 119 612 clause 5.7.1 TLSO profile.
    TrustedListOperatorProfile(TslSignerProfileEvidence),
    /// The signer DER matched a certificate in an already authenticated LOTL
    /// pointer and independently satisfied the TLSO certificate profile.
    AuthenticatedPointerCertificate(TslSignerProfileEvidence),
    /// The signer DER matched a certificate authenticated by an external,
    /// immutable bootstrap source.
    ExactExternalCertificate,
}

#[cfg(feature = "native")]
#[derive(zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
struct VerifiedSignerMaterial {
    signer_certificate_der: Vec<u8>,
    key_info_certificates_der: Vec<Vec<u8>>,
    signature_algorithm: TslSignatureAlgorithm,
}

/// Verify a TSL / LOTL XML document using XMLSec + OpenSSL.
///
/// SECURITY MODEL:
/// - XMLSec validates XMLDSig correctness
/// - KeyInfo provides signer identity
/// - reallyme-trust-core enforces trust anchors
///
/// PLATFORM:
/// - Native only (Linux / macOS)
/// - NOT available on WASM / mobile
///
pub fn verify_tsl_xml_openssl(
    xml: &str,
    trust_roots: &[X509Certificate],
    now: time::OffsetDateTime,
    policy: envelopes_x509::policy::X509Policy,
    status_checker: &dyn identity_revocation_core::StatusChecker,
) -> Result<VerifiedTrustedList, TslOpenSslError> {
    verify_tsl_xml_openssl_impl(
        xml,
        trust_roots,
        &[],
        TslSignerAuthorization::Community,
        now,
        policy,
        status_checker,
    )
}

/// Verify a trusted list using an exact signer authenticated by an external
/// bootstrap source, such as an EU LOTL certificate published in the Official
/// Journal. Exact DER, XMLDSig/XAdES, path/status, and signature-algorithm
/// policy still apply. The bootstrap certificate is not treated as a TLSO
/// certificate because Commission certificates can use a non-`EU` subject
/// country and broader EKUs. National/community entry points enforce TLSO.
pub fn verify_tsl_xml_openssl_with_external_signer(
    xml: &str,
    trust_roots: &[X509Certificate],
    externally_authorized_signer: &X509Certificate,
    now: time::OffsetDateTime,
    policy: envelopes_x509::policy::X509Policy,
    status_checker: &dyn identity_revocation_core::StatusChecker,
) -> Result<VerifiedTrustedList, TslOpenSslError> {
    verify_tsl_xml_openssl_impl(
        xml,
        trust_roots,
        &[],
        TslSignerAuthorization::ExactExternalCertificate(externally_authorized_signer),
        now,
        policy,
        status_checker,
    )
}

/// Verify a trusted list with authenticated same-community lists available for
/// the TS 119 612 clause 5.7.1 TLSO issuer restriction.
///
/// `community_lists` may authorize the issuer of the child list's TLSO
/// certificate when the lists share an authenticated scheme-community rule.
/// They never turn configured PKIX roots into authenticated LOTL pointer
/// certificates; exact pointer authorization requires the pointer identity and
/// target metadata to be carried through the traversal boundary.
pub fn verify_tsl_xml_openssl_with_community_lists(
    xml: &str,
    trust_roots: &[X509Certificate],
    community_lists: &[&VerifiedTrustedList],
    now: time::OffsetDateTime,
    policy: envelopes_x509::policy::X509Policy,
    status_checker: &dyn identity_revocation_core::StatusChecker,
) -> Result<VerifiedTrustedList, TslOpenSslError> {
    verify_tsl_xml_openssl_impl(
        xml,
        trust_roots,
        community_lists,
        TslSignerAuthorization::Community,
        now,
        policy,
        status_checker,
    )
}

/// Verify a fetched child list through one pointer in an already verified
/// parent LOTL.
///
/// The pointer URL, media type, list qualifiers, and signer certificate are
/// all taken from or checked against the authenticated parent. The caller
/// supplies transport bytes and PKIX roots, but cannot substitute those roots
/// for the pointer's signer authorization.
pub struct AuthenticatedPointerVerification<'a> {
    /// Previously verified parent LOTL that authenticated the pointer.
    pub parent: &'a VerifiedTrustedList,
    /// Index of the selected pointer in the authenticated parent.
    pub pointer_index: usize,
    /// Exact URL from which the child bytes were fetched.
    pub fetched_url: &'a str,
    /// Transport media type observed for the fetched child.
    pub fetched_media_type: TslMediaType,
    /// Fetched child XML bytes represented as UTF-8 text.
    pub xml: &'a str,
    /// Configured PKIX roots available for child signer path construction.
    pub trust_roots: &'a [X509Certificate],
    /// Caller-supplied verification time.
    pub now: time::OffsetDateTime,
    /// X.509 policy applied to the child signer path.
    pub policy: envelopes_x509::policy::X509Policy,
    /// Status checker applied to every required signer-path certificate.
    pub status_checker: &'a dyn identity_revocation_core::StatusChecker,
}

/// Verify a child list using one authenticated parent pointer request.
pub fn verify_tsl_xml_openssl_from_authenticated_pointer(
    request: AuthenticatedPointerVerification<'_>,
) -> Result<VerifiedTrustedList, TslOpenSslError> {
    validate_eu_lotl_parent(request.parent)?;
    // Pointer authorization is only valid while the authenticated parent LOTL
    // is fresh at the child verification time. Authentication at an earlier
    // instant must not turn an expired pointer set into a permanent grant.
    identity_trust_tsl_core::validate_tsl_freshness(request.parent.list(), request.now).map_err(
        |error| match error {
            identity_trust_tsl_core::TslError::Expired => TslOpenSslError::ExpiredTrustedList,
            other => TslOpenSslError::TrustedList(other),
        },
    )?;
    let pointer = request
        .parent
        .list()
        .pointers
        .get(request.pointer_index)
        .ok_or_else(pointer_target_mismatch)?;
    if pointer.url.as_str() != request.fetched_url {
        return Err(pointer_target_mismatch());
    }

    let verified = verify_tsl_xml_openssl_impl(
        request.xml,
        request.trust_roots,
        &[request.parent],
        TslSignerAuthorization::AuthenticatedPointer(pointer),
        request.now,
        request.policy,
        request.status_checker,
    )?;
    identity_trust_tsl_core::validate_pointer_target(
        pointer,
        verified.list(),
        request.fetched_media_type,
    )
    .map_err(map_tsl_core_error)?;
    Ok(verified)
}

fn validate_eu_lotl_parent(parent: &VerifiedTrustedList) -> Result<(), TslOpenSslError> {
    let externally_bootstrapped = matches!(
        parent.signer_authorization(),
        TslSignerAuthorizationEvidence::ExactExternalCertificate
    );
    let list = parent.list();
    if !externally_bootstrapped
        || list.tsl_type.as_str() != identity_trust_tsl_core::EU_LOTL_TSL_TYPE
        || list.scheme_territory.as_deref() != Some("EU")
    {
        return Err(TslOpenSslError::InvalidPointerParent);
    }
    Ok(())
}

fn pointer_target_mismatch() -> TslOpenSslError {
    TslOpenSslError::TrustedList(identity_trust_tsl_core::TslError::PointerPolicy(
        identity_trust_tsl_core::TslPointerPolicyFailure::TargetMetadataMismatch,
    ))
}

#[derive(Clone, Copy)]
enum TslSignerAuthorization<'a> {
    Community,
    AuthenticatedPointer(&'a TslPointer),
    ExactExternalCertificate(&'a X509Certificate),
}

#[cfg(feature = "native")]
fn verify_tsl_xml_openssl_impl(
    xml: &str,
    trust_roots: &[X509Certificate],
    community_lists: &[&VerifiedTrustedList],
    signer_authorization: TslSignerAuthorization<'_>,
    now: time::OffsetDateTime,
    policy: envelopes_x509::policy::X509Policy,
    status_checker: &dyn identity_revocation_core::StatusChecker,
) -> Result<VerifiedTrustedList, TslOpenSslError> {
    use envelopes_x509::parse_cert_der;
    use identity_trust_openssl::OpenSslSignatureVerifier;
    use identity_trust_tsl_core::parse_tsl_xml;
    use reallyme_trust_core::{evaluate_trust_decision, TrustConfig, TrustOutcome};

    let policy = bind_tsl_signer_policy(policy)?;

    // Root count and byte budgets are checked before XML parsing, OpenSSL DER
    // parsing, or backend allocation. This keeps configuration input from
    // moving work ahead of the trust core's fixed MAX_TRUST_ROOTS invariant.
    validate_trust_root_budget(trust_roots)?;

    // 1) Every configured root must be a well-formed certificate. Each root
    // is handed to XMLSec as its own DER certificate so that every configured
    // anchor is trusted, not only the first entry of a concatenated bundle.
    // XMLSec verifies only the XML signature and returns its exact KeyInfo
    // signer. Trust is evaluated once below against these explicit roots; the
    // C boundary deliberately disables ambient OpenSSL certificate stores.
    let mut trusted_roots_der: Vec<&[u8]> = Vec::new();
    trusted_roots_der
        .try_reserve_exact(trust_roots.len())
        .map_err(|_| TslOpenSslError::TrustRoots(TslTrustRootErrorReason::AllocationFailed))?;
    for root in trust_roots {
        openssl::x509::X509::from_der(&root.der).map_err(|_| {
            TslOpenSslError::TrustRoots(TslTrustRootErrorReason::InvalidCertificateDer)
        })?;
        trusted_roots_der.push(root.der.as_slice());
    }

    // 2) Verify XMLDSig before projecting attacker-controlled semantic
    // collections, then retain the exact backend-selected signer. The
    // returned receipt is already checked against this signature's KeyInfo, so
    // certificate selection cannot drift into an independent XML scan.
    identity_trust_tsl_core::validate_tsl_xml_boundary(xml).map_err(map_tsl_core_error)?;
    let exact_signer_candidates: Option<Vec<&[u8]>> = match signer_authorization {
        TslSignerAuthorization::AuthenticatedPointer(pointer) => {
            let certificates = pointer.certificates_der().collect::<Vec<_>>();
            if certificates.is_empty() {
                return Err(pointer_target_mismatch());
            }
            Some(certificates)
        }
        TslSignerAuthorization::ExactExternalCertificate(authorized) => {
            Some(vec![authorized.der.as_slice()])
        }
        TslSignerAuthorization::Community => None,
    };
    let verified_signature = verify_tsl_xmldsig(
        xml,
        &trusted_roots_der,
        now,
        exact_signer_candidates.as_deref(),
    )?;

    // 3) Only authenticated XML reaches potentially expensive projection.
    let tsl = parse_tsl_xml(xml).map_err(map_tsl_core_error)?;

    // ETSI TS 119 612 v2.4.1 clause 5.3.15 requires applications to discard
    // an expired TL. Apply caller-selected time only after XMLDSig has
    // authenticated the deadline, so unauthenticated XML cannot produce a
    // successful-looking freshness decision.
    identity_trust_tsl_core::validate_tsl_freshness(&tsl, now).map_err(|error| match error {
        identity_trust_tsl_core::TslError::Expired => TslOpenSslError::ExpiredTrustedList,
        other => TslOpenSslError::TrustedList(other),
    })?;

    let signer_der = verified_signature.signer_certificate_der.as_slice();
    let signer = parse_cert_der(signer_der).map_err(|_| TslOpenSslError::InvalidSigner)?;
    let directly_authorized_signer = match signer_authorization {
        TslSignerAuthorization::AuthenticatedPointer(pointer) => pointer
            .certificates_der()
            .find(|certificate| *certificate == signer.der.as_slice())
            .map(|_| signer.clone())
            .ok_or_else(pointer_target_mismatch)
            .map(Some)?,
        TslSignerAuthorization::ExactExternalCertificate(authorized) => {
            if signer.der != authorized.der {
                return Err(TslOpenSslError::ExternalSignerCertificateMismatch);
            }
            Some(authorized.clone())
        }
        TslSignerAuthorization::Community => None,
    };
    let signer_authorization = match signer_authorization {
        TslSignerAuthorization::Community => {
            TslSignerAuthorizationEvidence::TrustedListOperatorProfile(
                validate_tlso_signer_profile(
                    &signer,
                    &tsl,
                    community_lists,
                    now,
                    verified_signature.signature_algorithm,
                )?,
            )
        }
        TslSignerAuthorization::AuthenticatedPointer(_) => {
            TslSignerAuthorizationEvidence::AuthenticatedPointerCertificate(
                validate_tlso_signer_profile(
                    &signer,
                    &tsl,
                    community_lists,
                    now,
                    verified_signature.signature_algorithm,
                )?,
            )
        }
        TslSignerAuthorization::ExactExternalCertificate(_) => {
            TslSignerAuthorizationEvidence::ExactExternalCertificate
        }
    };
    let mut presented = vec![signer];
    for candidate_der in &verified_signature.key_info_certificates_der {
        if candidate_der.as_slice() == signer_der {
            continue;
        }
        let candidate =
            parse_cert_der(candidate_der).map_err(|_| TslOpenSslError::InvalidSigner)?;
        presented.push(candidate);
    }

    // 5) Validate signer trust chain
    let source = reallyme_trust_core::TrustSourceEvidence {
        source_id: sha256(tsl.tsl_type.as_str().as_bytes()),
        snapshot_id: sha256(xml.as_bytes()),
    };
    let direct_trust = directly_authorized_signer
        .map(|certificate| {
            vec![reallyme_trust_core::DirectTrustEntry {
                certificate,
                purpose: reallyme_trust_core::TrustPurpose::TrustedListSigner,
                policy_id: reallyme_trust_core::TrustPolicyId::EuTrustedListSignerV1,
                source,
            }]
        })
        .unwrap_or_default();
    let cfg = TrustConfig {
        trust_roots: trust_roots.to_vec(),
        now,
        policy,
        link_policy: Default::default(),
        evaluation: reallyme_trust_core::TrustEvaluationContext {
            purpose: reallyme_trust_core::TrustPurpose::TrustedListSigner,
            policy_id: reallyme_trust_core::TrustPolicyId::EuTrustedListSignerV1,
            source: Some(source),
            status_policy: reallyme_trust_core::CertificateStatusPolicy {
                leaf: reallyme_trust_core::StatusRequirement::Required,
                intermediates: reallyme_trust_core::StatusRequirement::Required,
                trust_anchor: reallyme_trust_core::StatusRequirement::Exempt,
            },
        },
        direct_trust,
    };

    let decision = evaluate_trust_decision(
        &presented,
        &cfg,
        &OpenSslSignatureVerifier,
        Some(status_checker),
    )
    .map_err(|error| TslOpenSslError::TrustFailure(map_trust_failure(error)))?;
    match decision.outcome() {
        TrustOutcome::Trusted => {}
        TrustOutcome::Rejected => {
            return Err(TslOpenSslError::TrustFailure(
                crate::error::TslSignerTrustFailureReason::Rejected,
            ));
        }
        TrustOutcome::Indeterminate => {
            return Err(TslOpenSslError::TrustFailure(
                crate::error::TslSignerTrustFailureReason::Indeterminate,
            ));
        }
        _ => {
            return Err(TslOpenSslError::TrustFailure(
                crate::error::TslSignerTrustFailureReason::Indeterminate,
            ));
        }
    }

    let signer_certificate_sha256 = sha256(signer_der);
    let key_info_certificate_sha256 = verified_signature
        .key_info_certificates_der
        .iter()
        .map(|certificate| sha256(certificate))
        .collect();

    // The list is returned without any time projection. Service states,
    // including pre-published future transitions and full service history,
    // remain intact; authorization selects the state effective at its own
    // trusted evaluation time and re-checks list freshness at that time.
    Ok(VerifiedTrustedList {
        list: tsl,
        signer_trust: decision,
        signer_certificate_sha256,
        key_info_certificate_sha256,
        signer_authorization,
        signature_algorithm: verified_signature.signature_algorithm,
    })
}

#[cfg(feature = "native")]
fn sha256(value: &[u8]) -> [u8; 32] {
    *reallyme_crypto::sha2::digest(value).as_bytes()
}

include!("verify/error_mapping.rs");

#[cfg(not(feature = "native"))]
fn verify_tsl_xml_openssl_impl(
    _xml: &str,
    _trust_roots: &[X509Certificate],
    _community_lists: &[&VerifiedTrustedList],
    signer_authorization: TslSignerAuthorization<'_>,
    _now: time::OffsetDateTime,
    policy: envelopes_x509::policy::X509Policy,
    _status_checker: &dyn identity_revocation_core::StatusChecker,
) -> Result<VerifiedTrustedList, TslOpenSslError> {
    let _ = bind_tsl_signer_policy(policy)?;
    // Retain the exact external certificate in the portable typed API despite no verifier.
    match signer_authorization {
        TslSignerAuthorization::AuthenticatedPointer(pointer) => {
            let _ = pointer.certificates_der().count();
        }
        TslSignerAuthorization::ExactExternalCertificate(certificate) => {
            let _ = certificate.der.len();
        }
        TslSignerAuthorization::Community => {}
    }
    Err(TslOpenSslError::BackendUnavailable)
}

#[cfg(test)]
#[path = "verify/authenticated_pointer_tests.rs"]
mod authenticated_pointer_tests;
