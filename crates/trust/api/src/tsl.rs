// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{TrustApiError, TrustApiResult};
use identity_trust_tsl_core::{parse_tsl_xml, TrustedList};

#[cfg(all(
    feature = "native",
    not(any(
        target_os = "android",
        target_os = "ios",
        target_os = "tvos",
        target_os = "watchos",
        target_os = "visionos"
    ))
))]
pub use identity_trust_tsl_openssl::VerifiedTrustedList;

#[cfg(all(
    feature = "native",
    not(any(
        target_os = "android",
        target_os = "ios",
        target_os = "tvos",
        target_os = "watchos",
        target_os = "visionos"
    ))
))]
const MAX_TRUST_LIST_XML_BYTES: usize = 16 * 1024 * 1024;

/// Trust anchors accepted for TSL / LOTL XMLDSig verification.
///
/// This type keeps signer trust material explicit at the trust layer. It does
/// not expose XMLSec state, raw handles, or process details to callers.
#[derive(Debug, Clone)]
#[cfg(all(
    feature = "native",
    not(any(
        target_os = "android",
        target_os = "ios",
        target_os = "tvos",
        target_os = "watchos",
        target_os = "visionos"
    ))
))]
pub struct TrustedListAnchors {
    roots: Vec<envelopes_x509::X509Certificate>,
}

#[cfg(all(
    feature = "native",
    not(any(
        target_os = "android",
        target_os = "ios",
        target_os = "tvos",
        target_os = "watchos",
        target_os = "visionos"
    ))
))]
impl TrustedListAnchors {
    /// Create trust-list anchors from already parsed X.509 certificates.
    pub fn new(roots: Vec<envelopes_x509::X509Certificate>) -> TrustApiResult<Self> {
        identity_trust_tsl_openssl::validate_tsl_trust_roots(&roots)
            .map_err(map_tsl_openssl_error)?;

        Ok(Self { roots })
    }

    /// Borrow the root certificates used to verify the TSL signer.
    pub fn roots(&self) -> &[envelopes_x509::X509Certificate] {
        &self.roots
    }
}

/// Parse a TSL / LOTL XML document without verifying XMLDSig.
pub fn parse_trust_list_xml(xml: &str) -> TrustApiResult<TrustedList> {
    parse_tsl_xml(xml).map_err(map_tsl_parse_error)
}

fn map_tsl_parse_error(error: identity_trust_tsl_core::TslError) -> TrustApiError {
    use crate::TrustedListPolicyErrorReason;
    use identity_trust_tsl_core::TslError;

    match error {
        TslError::InvalidTag => {
            TrustApiError::TrustedListPolicy(TrustedListPolicyErrorReason::InvalidTag)
        }
        TslError::InvalidUpdateWindow => {
            TrustApiError::TrustedListPolicy(TrustedListPolicyErrorReason::InvalidUpdateWindow)
        }
        TslError::Expired => {
            TrustApiError::TrustedListPolicy(TrustedListPolicyErrorReason::Expired)
        }
        TslError::UnsupportedCriticalExtension => TrustApiError::TrustedListPolicy(
            TrustedListPolicyErrorReason::UnsupportedCriticalExtension,
        ),
        other => TrustApiError::TrustedList(other),
    }
}

/// Ingest the EU List of Trusted Lists from raw XML bytes.
///
/// Native builds perform full XMLDSig verification before returning normalized
/// trust metadata. Callers are responsible for fetching XML and providing
/// trusted signer anchors from their deployment trust store.
#[cfg(all(
    feature = "native",
    not(any(
        target_os = "android",
        target_os = "ios",
        target_os = "tvos",
        target_os = "watchos",
        target_os = "visionos"
    ))
))]
pub fn ingest_eu_trusted_list(
    xml: &[u8],
    trust_anchors: &TrustedListAnchors,
    externally_authorized_signer: &envelopes_x509::X509Certificate,
    now: time::OffsetDateTime,
) -> TrustApiResult<VerifiedTrustedList> {
    let xml = trust_list_xml_from_bytes(xml)?;
    verify_trust_list_xml_native_with_external_signer(
        xml,
        trust_anchors.roots(),
        externally_authorized_signer,
        now,
        envelopes_x509::policy::X509Policy::default(),
    )
}

/// Ingest a named TSL / LOTL from raw XML bytes.
#[cfg(all(
    feature = "native",
    not(any(
        target_os = "android",
        target_os = "ios",
        target_os = "tvos",
        target_os = "watchos",
        target_os = "visionos"
    ))
))]
pub fn ingest_trusted_list_xml(
    xml: &[u8],
    trust_anchors: &TrustedListAnchors,
    now: time::OffsetDateTime,
) -> TrustApiResult<VerifiedTrustedList> {
    let xml = trust_list_xml_from_bytes(xml)?;
    verify_trust_list_xml_native(
        xml,
        trust_anchors.roots(),
        now,
        envelopes_x509::policy::X509Policy::default(),
    )
}

/// Verify a TSL / LOTL XML on native targets (xmlsec + OpenSSL).
#[cfg(all(
    feature = "native",
    not(any(
        target_os = "android",
        target_os = "ios",
        target_os = "tvos",
        target_os = "watchos",
        target_os = "visionos"
    ))
))]
pub fn verify_trust_list_xml_native(
    xml: &str,
    trust_roots: &[envelopes_x509::X509Certificate],
    now: time::OffsetDateTime,
    policy: envelopes_x509::policy::X509Policy,
) -> TrustApiResult<VerifiedTrustedList> {
    identity_trust_tsl_openssl::verify_tsl_xml_openssl(xml, trust_roots, now, policy)
        .map_err(map_tsl_openssl_error)
}

/// Verify an EU LOTL against the exact signing certificate authenticated from
/// the applicable Official Journal publication.
#[cfg(all(
    feature = "native",
    not(any(
        target_os = "android",
        target_os = "ios",
        target_os = "tvos",
        target_os = "watchos",
        target_os = "visionos"
    ))
))]
pub fn verify_trust_list_xml_native_with_external_signer(
    xml: &str,
    trust_roots: &[envelopes_x509::X509Certificate],
    externally_authorized_signer: &envelopes_x509::X509Certificate,
    now: time::OffsetDateTime,
    policy: envelopes_x509::policy::X509Policy,
) -> TrustApiResult<VerifiedTrustedList> {
    identity_trust_tsl_openssl::verify_tsl_xml_openssl_with_external_signer(
        xml,
        trust_roots,
        externally_authorized_signer,
        now,
        policy,
    )
    .map_err(map_tsl_openssl_error)
}

#[cfg(all(
    feature = "native",
    not(any(
        target_os = "android",
        target_os = "ios",
        target_os = "tvos",
        target_os = "watchos",
        target_os = "visionos"
    ))
))]
fn map_tsl_openssl_error(error: identity_trust_tsl_openssl::TslOpenSslError) -> TrustApiError {
    use crate::{TrustApiResourceLimitReason, TrustedListPolicyErrorReason};
    use identity_trust_tsl_openssl::{
        TslOpenSslError, TslSignerProfileFailureReason, TslTrustRootErrorReason,
    };

    match error {
        TslOpenSslError::TrustedList(reason) => map_tsl_parse_error(reason),
        TslOpenSslError::InvalidSignature => TrustApiError::InvalidSignature,
        TslOpenSslError::ExternalSignerCertificateMismatch => TrustApiError::TrustedListPolicy(
            TrustedListPolicyErrorReason::ExternalSignerCertificateMismatch,
        ),
        TslOpenSslError::TrustFailure(_) => TrustApiError::NotTrusted,
        TslOpenSslError::SignerProfile(reason) => TrustApiError::TrustedListPolicy(match reason {
            TslSignerProfileFailureReason::UnauthorizedIssuer => {
                TrustedListPolicyErrorReason::UnauthorizedIssuer
            }
            TslSignerProfileFailureReason::CommunityListLimit => {
                TrustedListPolicyErrorReason::CommunityListLimit
            }
            TslSignerProfileFailureReason::CountryMismatch => {
                TrustedListPolicyErrorReason::CountryMismatch
            }
            TslSignerProfileFailureReason::OrganizationMismatch => {
                TrustedListPolicyErrorReason::OrganizationMismatch
            }
            TslSignerProfileFailureReason::MissingKeyUsage => {
                TrustedListPolicyErrorReason::MissingKeyUsage
            }
            TslSignerProfileFailureReason::InvalidKeyUsage => {
                TrustedListPolicyErrorReason::InvalidKeyUsage
            }
            TslSignerProfileFailureReason::MissingSubjectKeyIdentifier => {
                TrustedListPolicyErrorReason::MissingSubjectKeyIdentifier
            }
            TslSignerProfileFailureReason::InvalidSubjectKeyIdentifier => {
                TrustedListPolicyErrorReason::InvalidSubjectKeyIdentifier
            }
            TslSignerProfileFailureReason::InvalidBasicConstraints => {
                TrustedListPolicyErrorReason::InvalidBasicConstraints
            }
            TslSignerProfileFailureReason::InvalidExtendedKeyUsage => {
                TrustedListPolicyErrorReason::InvalidExtendedKeyUsage
            }
            TslSignerProfileFailureReason::AlgorithmLifetime => {
                TrustedListPolicyErrorReason::AlgorithmLifetime
            }
        }),
        TslOpenSslError::SignatureProfile(reason) => TrustApiError::TrustedListPolicy(
            TrustedListPolicyErrorReason::SignatureProfile(map_signature_profile_reason(reason)),
        ),
        TslOpenSslError::InvalidTag => {
            TrustApiError::TrustedListPolicy(TrustedListPolicyErrorReason::InvalidTag)
        }
        TslOpenSslError::InvalidUpdateWindow => {
            TrustApiError::TrustedListPolicy(TrustedListPolicyErrorReason::InvalidUpdateWindow)
        }
        TslOpenSslError::ExpiredTrustedList => {
            TrustApiError::TrustedListPolicy(TrustedListPolicyErrorReason::Expired)
        }
        TslOpenSslError::UnsupportedCriticalExtension => TrustApiError::TrustedListPolicy(
            TrustedListPolicyErrorReason::UnsupportedCriticalExtension,
        ),
        TslOpenSslError::InvalidXml
        | TslOpenSslError::InvalidSigner
        | TslOpenSslError::TrustRoots(TslTrustRootErrorReason::Empty)
        | TslOpenSslError::TrustRoots(TslTrustRootErrorReason::InvalidCertificateDer) => {
            TrustApiError::InvalidInput
        }
        TslOpenSslError::TrustRoots(TslTrustRootErrorReason::TooManyTrustRoots) => {
            TrustApiError::ResourceLimit(TrustApiResourceLimitReason::TooManyTrustRoots)
        }
        TslOpenSslError::TrustRoots(TslTrustRootErrorReason::CertificateDerTooLarge) => {
            TrustApiError::ResourceLimit(TrustApiResourceLimitReason::CertificateDerTooLarge)
        }
        TslOpenSslError::TrustRoots(TslTrustRootErrorReason::PemBundleTooLarge) => {
            TrustApiError::ResourceLimit(TrustApiResourceLimitReason::PemBundleTooLarge)
        }
        TslOpenSslError::TrustRoots(TslTrustRootErrorReason::AllocationFailed) => {
            TrustApiError::ResourceLimit(TrustApiResourceLimitReason::AllocationFailed)
        }
        TslOpenSslError::BackendUnavailable | TslOpenSslError::Internal => {
            TrustApiError::BackendFailure
        }
    }
}

#[cfg(all(
    feature = "native",
    not(any(
        target_os = "android",
        target_os = "ios",
        target_os = "tvos",
        target_os = "watchos",
        target_os = "visionos"
    ))
))]
const fn map_signature_profile_reason(
    reason: identity_trust_tsl_openssl::TslSignatureProfileFailureReason,
) -> crate::TrustedListSignatureProfileErrorReason {
    use crate::TrustedListSignatureProfileErrorReason as ApiReason;
    use identity_trust_tsl_openssl::TslSignatureProfileFailureReason as NativeReason;

    match reason {
        NativeReason::InvalidRootElement => ApiReason::InvalidRootElement,
        NativeReason::MissingRootId => ApiReason::MissingRootId,
        NativeReason::MissingRootElement => ApiReason::MissingRootElement,
        NativeReason::RetrievalMethodNotAllowed => ApiReason::RetrievalMethodNotAllowed,
        NativeReason::KeyInfoReferenceNotAllowed => ApiReason::KeyInfoReferenceNotAllowed,
        NativeReason::NonSameDocumentReference => ApiReason::NonSameDocumentReference,
        NativeReason::InvalidSignatureProfile => ApiReason::InvalidSignatureProfile,
        NativeReason::DuplicateId => ApiReason::DuplicateId,
        NativeReason::UnsupportedAlgorithm => ApiReason::UnsupportedAlgorithm,
        NativeReason::SignerBindingMismatch => ApiReason::SignerBindingMismatch,
        NativeReason::RootTransformProfile => ApiReason::RootTransformProfile,
        NativeReason::InvalidSignedProperties => ApiReason::InvalidSignedProperties,
        NativeReason::InvalidSigningCertificate => ApiReason::InvalidSigningCertificate,
        NativeReason::InvalidSigningTime => ApiReason::InvalidSigningTime,
        NativeReason::InvalidDataObjectFormat => ApiReason::InvalidDataObjectFormat,
        NativeReason::SigningCertificateMismatch => ApiReason::SigningCertificateMismatch,
        NativeReason::KeyInfoCertificateCount => ApiReason::KeyInfoCertificateCount,
    }
}

/// Verify a TSL with prior authenticated same-community lists available for
/// the TS 119 612 signer-issuer restriction.
#[cfg(all(
    feature = "native",
    not(any(
        target_os = "android",
        target_os = "ios",
        target_os = "tvos",
        target_os = "watchos",
        target_os = "visionos"
    ))
))]
pub fn verify_trust_list_xml_native_with_community_lists(
    xml: &str,
    trust_roots: &[envelopes_x509::X509Certificate],
    community_lists: &[&VerifiedTrustedList],
    now: time::OffsetDateTime,
    policy: envelopes_x509::policy::X509Policy,
) -> TrustApiResult<VerifiedTrustedList> {
    identity_trust_tsl_openssl::verify_tsl_xml_openssl_with_community_lists(
        xml,
        trust_roots,
        community_lists,
        now,
        policy,
    )
    .map_err(map_tsl_openssl_error)
}

#[cfg(all(
    feature = "native",
    not(any(
        target_os = "android",
        target_os = "ios",
        target_os = "tvos",
        target_os = "watchos",
        target_os = "visionos"
    ))
))]
fn trust_list_xml_from_bytes(xml: &[u8]) -> TrustApiResult<&str> {
    if xml.is_empty() || xml.len() > MAX_TRUST_LIST_XML_BYTES {
        return Err(TrustApiError::InvalidInput);
    }

    std::str::from_utf8(xml).map_err(|_| TrustApiError::InvalidInput)
}
