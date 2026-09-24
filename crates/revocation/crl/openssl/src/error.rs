// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_ssi_proto::generated::proto::reallyme::identity_core::v1::IdentityCoreErrorReason;
use thiserror::Error;

/// Typed failures from the OpenSSL CRL backend.
#[derive(Debug, Error)]
pub enum CrlError {
    /// CRL encoding could not be parsed.
    #[error("invalid CRL encoding")]
    InvalidCrl,

    /// Issuer certificate required to verify the CRL was missing.
    #[error("missing issuer certificate for CRL")]
    MissingIssuer,

    /// CRL signature verification failed.
    #[error("CRL signature verification failed")]
    BadSignature,

    /// CRL validity window failed policy.
    #[error("CRL is expired or not yet valid")]
    InvalidTime,

    /// CRL format or algorithm is unsupported.
    #[error("unsupported or unknown CRL format")]
    Unsupported,
}

impl From<CrlError> for IdentityCoreErrorReason {
    fn from(error: CrlError) -> Self {
        match error {
            CrlError::InvalidCrl => {
                Self::IDENTITY_CORE_ERROR_REASON_CREDENTIAL_STATUS_INVALID_EVIDENCE
            }
            CrlError::MissingIssuer => Self::IDENTITY_CORE_ERROR_REASON_TRUST_CHAIN_INVALID,
            CrlError::BadSignature => {
                Self::IDENTITY_CORE_ERROR_REASON_CREDENTIAL_STATUS_INVALID_SIGNATURE
            }
            CrlError::InvalidTime => {
                Self::IDENTITY_CORE_ERROR_REASON_CREDENTIAL_STATUS_INVALID_TIME_WINDOW
            }
            CrlError::Unsupported => Self::IDENTITY_CORE_ERROR_REASON_REVOCATION_STATUS_UNSUPPORTED,
        }
    }
}

#[cfg(test)]
#[path = "error_proto_error_tests.rs"]
mod proto_error_tests;
