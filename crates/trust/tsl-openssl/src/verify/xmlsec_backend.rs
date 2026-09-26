// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{TslOpenSslError, VerifiedSignerMaterial};
#[cfg(feature = "xmlsec-ffi")]
use crate::error::TslTrustRootErrorReason;

#[cfg(feature = "xmlsec-ffi")]
pub(super) fn verify_tsl_xmldsig(
    xml: &str,
    trusted_roots_der: &[&[u8]],
    verification_time: time::OffsetDateTime,
    exact_signer_candidates_der: Option<&[&[u8]]>,
) -> Result<VerifiedSignerMaterial, TslOpenSslError> {
    let verified = match exact_signer_candidates_der {
        Some(expected_signers_der) => {
            identity_trust_tsl_xmlsec::verify_tsl_xmldsig_xmlsec_with_exact_signers(
                xml,
                trusted_roots_der,
                verification_time,
                expected_signers_der,
            )
            .map_err(map_exact_signer_error)?
        }
        None => identity_trust_tsl_xmlsec::verify_tsl_xmldsig_xmlsec(
            xml,
            trusted_roots_der,
            verification_time,
        )
        .map_err(map_xmlsec_ffi_error)?,
    };
    Ok(VerifiedSignerMaterial {
        signer_certificate_der: verified.signer_certificate_der().to_vec(),
        key_info_certificates_der: verified.key_info_certificates_der().to_vec(),
        signature_algorithm: match verified.signature_algorithm() {
            identity_trust_tsl_xmlsec::TslXmlSignatureAlgorithm::RsaSha256 => {
                crate::signer_profile::TslSignatureAlgorithm::RsaSha256
            }
            identity_trust_tsl_xmlsec::TslXmlSignatureAlgorithm::RsaSha384 => {
                crate::signer_profile::TslSignatureAlgorithm::RsaSha384
            }
            identity_trust_tsl_xmlsec::TslXmlSignatureAlgorithm::RsaSha512 => {
                crate::signer_profile::TslSignatureAlgorithm::RsaSha512
            }
            identity_trust_tsl_xmlsec::TslXmlSignatureAlgorithm::RsaPssSha256 => {
                crate::signer_profile::TslSignatureAlgorithm::RsaPssSha256
            }
            identity_trust_tsl_xmlsec::TslXmlSignatureAlgorithm::RsaPssSha384 => {
                crate::signer_profile::TslSignatureAlgorithm::RsaPssSha384
            }
            identity_trust_tsl_xmlsec::TslXmlSignatureAlgorithm::RsaPssSha512 => {
                crate::signer_profile::TslSignatureAlgorithm::RsaPssSha512
            }
            identity_trust_tsl_xmlsec::TslXmlSignatureAlgorithm::EcdsaSha256 => {
                crate::signer_profile::TslSignatureAlgorithm::EcdsaSha256
            }
            identity_trust_tsl_xmlsec::TslXmlSignatureAlgorithm::EcdsaSha384 => {
                crate::signer_profile::TslSignatureAlgorithm::EcdsaSha384
            }
            identity_trust_tsl_xmlsec::TslXmlSignatureAlgorithm::EcdsaSha512 => {
                crate::signer_profile::TslSignatureAlgorithm::EcdsaSha512
            }
        },
    })
}

#[cfg(feature = "xmlsec-ffi")]
fn map_exact_signer_error(error: identity_trust_tsl_xmlsec::XmlSecError) -> TslOpenSslError {
    if matches!(
        error,
        identity_trust_tsl_xmlsec::XmlSecError::PolicyViolation(
            identity_trust_tsl_xmlsec::XmlSecPolicyViolationReason::SignerBindingMismatch
        )
    ) {
        return TslOpenSslError::ExternalSignerCertificateMismatch;
    }
    map_xmlsec_ffi_error(error)
}

#[cfg(feature = "xmlsec-ffi")]
fn map_xmlsec_ffi_error(error: identity_trust_tsl_xmlsec::XmlSecError) -> TslOpenSslError {
    match error {
        identity_trust_tsl_xmlsec::XmlSecError::InvalidSignature => {
            TslOpenSslError::InvalidSignature
        }
        identity_trust_tsl_xmlsec::XmlSecError::BackendUnavailable => {
            TslOpenSslError::BackendUnavailable
        }
        identity_trust_tsl_xmlsec::XmlSecError::SchemaValidationFailed => {
            TslOpenSslError::InvalidXml
        }
        identity_trust_tsl_xmlsec::XmlSecError::PolicyViolation(reason) => {
            TslOpenSslError::SignatureProfile(super::map_xmlsec_policy_reason(reason))
        }
        identity_trust_tsl_xmlsec::XmlSecError::TrustRoots(reason) => {
            TslOpenSslError::TrustRoots(map_trust_root_reason(reason))
        }
        identity_trust_tsl_xmlsec::XmlSecError::Internal => TslOpenSslError::Internal,
    }
}

#[cfg(feature = "xmlsec-ffi")]
const fn map_trust_root_reason(
    reason: identity_trust_tsl_xmlsec::XmlSecTrustRootErrorReason,
) -> TslTrustRootErrorReason {
    use identity_trust_tsl_xmlsec::XmlSecTrustRootErrorReason as XmlSecReason;

    match reason {
        XmlSecReason::Empty => TslTrustRootErrorReason::Empty,
        XmlSecReason::TooManyTrustRoots => TslTrustRootErrorReason::TooManyTrustRoots,
        XmlSecReason::CertificateDerTooLarge => TslTrustRootErrorReason::CertificateDerTooLarge,
        XmlSecReason::InvalidCertificateDer => TslTrustRootErrorReason::InvalidCertificateDer,
    }
}

#[cfg(not(feature = "xmlsec-ffi"))]
pub(super) fn verify_tsl_xmldsig(
    _xml: &str,
    _trusted_roots_der: &[&[u8]],
    _verification_time: time::OffsetDateTime,
    _exact_signer_candidates_der: Option<&[&[u8]]>,
) -> Result<VerifiedSignerMaterial, TslOpenSslError> {
    // Provider selection is explicit. Searching PATH for `xmlsec1` would make
    // verification depend on mutable ambient process state and could silently
    // select an unaudited binary.
    Err(TslOpenSslError::BackendUnavailable)
}
