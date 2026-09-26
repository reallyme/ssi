// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_ssi_proto::generated::proto::reallyme::identity_core::v1::IdentityCoreErrorReason;
use thiserror::Error;

/// Typed failures from the OpenSSL CRL backend.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum CrlError {
    /// CRL encoding could not be parsed.
    #[error("invalid CRL encoding")]
    InvalidCrl,

    /// Issuer certificate required to verify the CRL was missing.
    #[error("missing issuer certificate for CRL")]
    MissingIssuer,

    /// The CRL issuer name does not match the supplied issuer certificate.
    #[error("CRL issuer does not match issuer certificate")]
    IssuerMismatch,

    /// CRL signature verification failed.
    #[error("CRL signature verification failed")]
    BadSignature,

    /// CRL validity window is malformed or `nextUpdate` is absent.
    #[error("CRL is expired or not yet valid")]
    InvalidTime,

    /// CRL format or algorithm is unsupported.
    #[error("unsupported or unknown CRL format")]
    Unsupported,

    /// The CRL is a delta CRL, is scoped by an issuing distribution point, or
    /// is an indirect CRL; only complete, direct, unscoped CRLs are accepted.
    #[error("unsupported CRL scope")]
    UnsupportedScope,

    /// The CRL or one of its entries carries an unrecognized critical extension.
    #[error("unsupported critical CRL extension")]
    UnsupportedCriticalExtension,

    /// The CRL exceeds the accepted encoding or entry bounds.
    #[error("CRL exceeds accepted bounds")]
    TooLarge,
}

impl From<CrlError> for IdentityCoreErrorReason {
    fn from(error: CrlError) -> Self {
        match error {
            CrlError::InvalidCrl | CrlError::TooLarge => {
                Self::IDENTITY_CORE_ERROR_REASON_CREDENTIAL_STATUS_INVALID_EVIDENCE
            }
            CrlError::MissingIssuer | CrlError::IssuerMismatch => {
                Self::IDENTITY_CORE_ERROR_REASON_TRUST_CHAIN_INVALID
            }
            CrlError::BadSignature => {
                Self::IDENTITY_CORE_ERROR_REASON_CREDENTIAL_STATUS_INVALID_SIGNATURE
            }
            CrlError::InvalidTime => {
                Self::IDENTITY_CORE_ERROR_REASON_CREDENTIAL_STATUS_INVALID_TIME_WINDOW
            }
            CrlError::Unsupported
            | CrlError::UnsupportedScope
            | CrlError::UnsupportedCriticalExtension => {
                Self::IDENTITY_CORE_ERROR_REASON_REVOCATION_STATUS_UNSUPPORTED
            }
        }
    }
}

#[cfg(test)]
#[path = "error_proto_error_tests.rs"]
mod proto_error_tests;
