// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use thiserror::Error;

use envelopes_x509::X509Certificate;
use identity_trust_tsl_core::TrustedList;
use reallyme_ssi_proto::generated::proto::reallyme::identity_core::v1::IdentityCoreErrorReason;

/// Verification errors for the WASM trust backend.
#[derive(Debug, Error)]
pub enum TslWasmError {
    /// TSL XML could not be parsed.
    #[error("invalid XML")]
    InvalidXml,

    /// XML signing certificate could not be extracted or parsed.
    #[error("unable to extract signing certificate")]
    InvalidSigner,

    /// TSL signer certificate is not trusted under supplied policy.
    #[error("TSL signer is not trusted")]
    TrustFailure(TslSignerTrustFailureReason),

    /// XMLDSig verification is not available in this backend.
    #[error("XMLDSig verification is unavailable in WASM builds; use a native xmlsec backend or pre-verified trust metadata")]
    XmlDsigUnavailable,
}

/// Non-secret reason code for TSL signer trust failure.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum TslSignerTrustFailureReason {
    /// No trust path reached a configured root.
    #[error("no valid trust path")]
    NoValidPath,

    /// Signer certificate was outside its validity window.
    #[error("invalid signer validity time")]
    InvalidTime,

    /// Chain-link policy failed.
    #[error("chain linkage policy violation")]
    ChainLinkPolicy,

    /// Signer certificate signature failed verification.
    #[error("invalid signer signature")]
    InvalidSignature,

    /// Signer certificate was revoked.
    #[error("signer certificate revoked")]
    Revoked,

    /// Signer status check failed.
    #[error("signer status check failed")]
    StatusFailure,

    /// Internal trust evaluation failed.
    #[error("internal trust evaluation failure")]
    Internal,
}

impl From<TslSignerTrustFailureReason> for IdentityCoreErrorReason {
    fn from(reason: TslSignerTrustFailureReason) -> Self {
        match reason {
            TslSignerTrustFailureReason::NoValidPath => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_SIGNER_NO_VALID_PATH
            }
            TslSignerTrustFailureReason::InvalidTime => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_SIGNER_INVALID_TIME
            }
            TslSignerTrustFailureReason::ChainLinkPolicy => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_SIGNER_CHAIN_LINK_POLICY
            }
            TslSignerTrustFailureReason::InvalidSignature => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_SIGNER_INVALID_SIGNATURE
            }
            TslSignerTrustFailureReason::Revoked => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_SIGNER_REVOKED
            }
            TslSignerTrustFailureReason::StatusFailure => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_SIGNER_STATUS_FAILURE
            }
            TslSignerTrustFailureReason::Internal => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_SIGNER_INTERNAL
            }
        }
    }
}

impl From<TslWasmError> for IdentityCoreErrorReason {
    fn from(reason: TslWasmError) -> Self {
        match reason {
            TslWasmError::InvalidXml => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_WASM_INVALID_XML
            }
            TslWasmError::InvalidSigner => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_WASM_INVALID_SIGNER
            }
            TslWasmError::TrustFailure(reason) => reason.into(),
            TslWasmError::XmlDsigUnavailable => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_WASM_XMLDSIG_UNAVAILABLE
            }
        }
    }
}

/// Full TSL verification in WASM is currently unavailable because it requires XMLDSig
/// canonicalization + transform processing compatible with ETSI TS 119 612.
pub fn verify_tsl_xml_wasm(
    _name: &str,
    _xml: &str,
    _trust_roots: &[X509Certificate],
    _now: time::OffsetDateTime,
    _policy: envelopes_x509::policy::X509Policy,
) -> Result<TrustedList, TslWasmError> {
    Err(TslWasmError::XmlDsigUnavailable)
}

#[cfg(test)]
#[path = "tsl_proto_error_tests.rs"]
mod proto_error_tests;
