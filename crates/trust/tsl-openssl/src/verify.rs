// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use envelopes_x509::X509Certificate;
use identity_trust_tsl_core::TrustedList;

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

#[cfg(feature = "native")]
mod xmlsec_backend;
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

impl VerifiedTrustedList {
    /// Borrows the authenticated normalized trusted list.
    #[must_use]
    pub const fn list(&self) -> &TrustedList {
        &self.list
    }

    /// Borrows the signer path and status decision.
    #[must_use]
    pub const fn signer_trust(&self) -> &reallyme_trust_core::TrustDecision {
        &self.signer_trust
    }

    /// Returns the SHA-256 identity of the certificate that verified the XML signature.
    #[must_use]
    pub const fn signer_certificate_sha256(&self) -> [u8; 32] {
        self.signer_certificate_sha256
    }

    /// Borrows SHA-256 identities of certificates in the signature's KeyInfo.
    #[must_use]
    pub fn key_info_certificate_sha256(&self) -> &[[u8; 32]] {
        &self.key_info_certificate_sha256
    }

    /// Returns the signer-authorization policy evidence.
    #[must_use]
    pub const fn signer_authorization(&self) -> TslSignerAuthorizationEvidence {
        self.signer_authorization
    }

    /// Returns the TLSO profile evidence when TS 119 612 clause 5.7.1 was selected.
    #[must_use]
    pub const fn signer_profile(&self) -> Option<TslSignerProfileEvidence> {
        match self.signer_authorization {
            TslSignerAuthorizationEvidence::TrustedListOperatorProfile(evidence) => Some(evidence),
            TslSignerAuthorizationEvidence::ExactAuthenticatedPointerCertificate
            | TslSignerAuthorizationEvidence::ExactExternalCertificate => None,
        }
    }

    /// Returns the authenticated XML signature suite admitted by policy.
    #[must_use]
    pub const fn signature_algorithm(&self) -> TslSignatureAlgorithm {
        self.signature_algorithm
    }

    /// Reject this list when it is older than the last list the caller
    /// accepted for the same location (TS 119 612 clause 5.3.2).
    ///
    /// Signature verification alone cannot detect replay of an authentic but
    /// superseded list. Callers that persist the last accepted
    /// `TSLSequenceNumber` per list location should call this before
    /// replacing their stored list.
    pub fn validate_sequence_number(
        &self,
        last_accepted_sequence_number: u64,
    ) -> Result<(), TslOpenSslError> {
        identity_trust_tsl_core::validate_tsl_sequence_number(
            &self.list,
            last_accepted_sequence_number,
        )
        .map_err(TslOpenSslError::TrustedList)
    }
}

/// Authenticated policy used to authorize the XML signature certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TslSignerAuthorizationEvidence {
    /// The signer satisfied the TS 119 612 clause 5.7.1 TLSO profile.
    TrustedListOperatorProfile(TslSignerProfileEvidence),
    /// The signer DER matched a certificate in an already authenticated LOTL
    /// pointer. The pointer is the delegation trust boundary; the leaf still
    /// passed XMLDSig, XAdES, time, and SSI trust evaluation.
    ExactAuthenticatedPointerCertificate,
    /// The signer DER matched a certificate authenticated by an external,
    /// immutable bootstrap source.
    ExactExternalCertificate,
}

impl core::fmt::Debug for VerifiedTrustedList {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("VerifiedTrustedList([REDACTED])")
    }
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

/// Verify a trusted list whose exact signing certificate was authenticated by
/// an external bootstrap source.
///
/// EU LOTL cold-start authorization is supplied by the applicable Official
/// Journal publication (for example OJ C/2026/1944), from which the caller
/// must obtain the exact certificate. The externally pinned certificate is
/// deliberately not reclassified as a TS 119 612 TLSO certificate: current
/// Commission LOTL certificates can have a non-`EU` Subject country and
/// general client-authentication/email-protection EKUs. XMLDSig/XAdES, exact
/// DER binding, certificate path/status, and signature-algorithm policy still
/// apply. Ordinary national/community verification must use the default entry
/// points and the full TLSO profile.
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

/// Verify a trusted list against exact signer leaves from an authenticated
/// LOTL pointer.
///
/// TS 119 612 clause 5.3.13 binds these certificates to the child location.
/// They are leaf identities rather than CA roots, so each rollover certificate
/// is tried by exact DER binding. Only receipts returned by this verifier can
/// enter `community_lists`; those receipts remain available to the ordinary
/// clause 5.7.1 profile entry point.
pub fn verify_tsl_xml_openssl_with_community_lists(
    xml: &str,
    trust_roots: &[X509Certificate],
    community_lists: &[&VerifiedTrustedList],
    now: time::OffsetDateTime,
    policy: envelopes_x509::policy::X509Policy,
    status_checker: &dyn identity_revocation_core::StatusChecker,
) -> Result<VerifiedTrustedList, TslOpenSslError> {
    // A LOTL pointer authenticates TLSO leaf certificates, not CA roots.
    // XMLSec is therefore allowed to use an authenticated leaf as its
    // terminal verification key. The signature profile pre-pass and the
    // XMLDSig verification each run once; the backend-selected signer must
    // then equal exactly one authenticated rollover certificate. Exact pointer
    // authorization replaces the separate TLSO certificate-chain profile;
    // XMLDSig verification and the purpose-bound SSI direct-trust evaluation
    // still run below.
    verify_tsl_xml_openssl_impl(
        xml,
        trust_roots,
        community_lists,
        TslSignerAuthorization::AuthenticatedPointerCertificates(trust_roots),
        now,
        policy,
        status_checker,
    )
}

#[derive(Clone, Copy)]
enum TslSignerAuthorization<'a> {
    Community,
    AuthenticatedPointerCertificates(&'a [X509Certificate]),
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

    // Root count and byte budgets are checked before XML parsing, OpenSSL DER
    // parsing, or backend allocation. This keeps configuration input from
    // moving work ahead of the trust core's fixed MAX_TRUST_ROOTS invariant.
    validate_trust_root_budget(trust_roots)?;

    // 1) Parse semantics after the cheaper configuration boundary.
    let tsl = parse_tsl_xml(xml).map_err(map_tsl_core_error)?;

    // 2) Every configured root must be a well-formed certificate. Each root
    // is handed to XMLSec as its own DER certificate so that every configured
    // anchor is trusted, not only the first entry of a concatenated bundle.
    // XMLSec validates the X.509 chain before it will accept the key material
    // from KeyInfo. We *also* validate trust below; this is purely to allow
    // XMLSec to do the XMLDSig math.
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

    // 3) Verify XMLDSig and receive the exact backend-selected signer. The
    // returned receipt is already checked against this signature's KeyInfo, so
    // certificate selection cannot drift into an independent XML scan.
    let exact_signer_candidates: Option<Vec<&[u8]>> = match signer_authorization {
        TslSignerAuthorization::AuthenticatedPointerCertificates(authorized) => Some(
            authorized
                .iter()
                .map(|certificate| certificate.der.as_slice())
                .collect(),
        ),
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
        TslSignerAuthorization::AuthenticatedPointerCertificates(authorized) => Some(
            authorized
                .iter()
                .find(|certificate| certificate.der == signer.der)
                .ok_or(TslOpenSslError::ExternalSignerCertificateMismatch)?
                .clone(),
        ),
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
        TslSignerAuthorization::AuthenticatedPointerCertificates(_) => {
            TslSignerAuthorizationEvidence::ExactAuthenticatedPointerCertificate
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
    match decision.outcome {
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
fn map_tsl_core_error(error: identity_trust_tsl_core::TslError) -> TslOpenSslError {
    match error {
        identity_trust_tsl_core::TslError::InvalidTag => TslOpenSslError::InvalidTag,
        identity_trust_tsl_core::TslError::InvalidUpdateWindow => {
            TslOpenSslError::InvalidUpdateWindow
        }
        identity_trust_tsl_core::TslError::UnsupportedCriticalExtension => {
            TslOpenSslError::UnsupportedCriticalExtension
        }
        other => TslOpenSslError::TrustedList(other),
    }
}

#[cfg(feature = "native")]
fn sha256(value: &[u8]) -> [u8; 32] {
    *reallyme_crypto::sha2::digest(value).as_bytes()
}

include!("verify/error_mapping.rs");

#[cfg(feature = "native")]
fn map_trust_failure(
    error: reallyme_trust_core::TrustError,
) -> crate::error::TslSignerTrustFailureReason {
    use crate::error::TslSignerTrustFailureReason;

    match error {
        reallyme_trust_core::TrustError::NoValidPath => TslSignerTrustFailureReason::NoValidPath,
        reallyme_trust_core::TrustError::InvalidTime => TslSignerTrustFailureReason::InvalidTime,
        reallyme_trust_core::TrustError::ChainLinkPolicy(_) => {
            TslSignerTrustFailureReason::ChainLinkPolicy
        }
        reallyme_trust_core::TrustError::InvalidSignature => {
            TslSignerTrustFailureReason::InvalidSignature
        }
        reallyme_trust_core::TrustError::Revoked => TslSignerTrustFailureReason::Revoked,
        reallyme_trust_core::TrustError::StatusFailure => {
            TslSignerTrustFailureReason::StatusFailure
        }
        reallyme_trust_core::TrustError::Internal => TslSignerTrustFailureReason::Internal,
        reallyme_trust_core::TrustError::PurposePolicyMismatch => {
            TslSignerTrustFailureReason::Internal
        }
        reallyme_trust_core::TrustError::ResourceLimit(_) => {
            TslSignerTrustFailureReason::ResourceLimit
        }
    }
}

#[cfg(not(feature = "native"))]
fn verify_tsl_xml_openssl_impl(
    _xml: &str,
    _trust_roots: &[X509Certificate],
    _community_lists: &[&VerifiedTrustedList],
    signer_authorization: TslSignerAuthorization<'_>,
    _now: time::OffsetDateTime,
    _policy: envelopes_x509::policy::X509Policy,
    _status_checker: &dyn identity_revocation_core::StatusChecker,
) -> Result<VerifiedTrustedList, TslOpenSslError> {
    // Retain the exact external certificate in the portable typed API despite no verifier.
    match signer_authorization {
        TslSignerAuthorization::AuthenticatedPointerCertificates(certificates) => {
            let _ = certificates.len();
        }
        TslSignerAuthorization::ExactExternalCertificate(certificate) => {
            let _ = certificate.der.len();
        }
        TslSignerAuthorization::Community => {}
    }
    Err(TslOpenSslError::BackendUnavailable)
}
