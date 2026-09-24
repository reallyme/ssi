// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_ssi_proto::generated::proto::reallyme::identity_core::v1::IdentityCoreErrorReason;
use thiserror::Error;

/// Typed OCSP status-check failures.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum OcspError {
    /// Certificate status is revoked.
    #[error("certificate revoked")]
    Revoked,

    /// Responder reported an unknown certificate status.
    #[error("certificate status unknown")]
    Unknown,

    /// OCSP response freshness failed policy.
    #[error("OCSP response expired")]
    Expired,

    /// OCSP response shape or required metadata was invalid.
    #[error("invalid OCSP response")]
    InvalidResponse,

    /// OCSP responder authorization failed policy.
    #[error("OCSP responder not trusted")]
    UntrustedResponder,

    /// OCSP backend was unavailable.
    #[error("OCSP backend unavailable")]
    Unavailable,
}

impl From<OcspError> for IdentityCoreErrorReason {
    fn from(error: OcspError) -> Self {
        match error {
            OcspError::Revoked => Self::IDENTITY_CORE_ERROR_REASON_CREDENTIAL_STATUS_REVOKED,
            OcspError::Unknown => Self::IDENTITY_CORE_ERROR_REASON_CREDENTIAL_STATUS_CHECK_FAILED,
            OcspError::Expired => Self::IDENTITY_CORE_ERROR_REASON_CREDENTIAL_STATUS_EXPIRED,
            OcspError::InvalidResponse => {
                Self::IDENTITY_CORE_ERROR_REASON_CREDENTIAL_STATUS_INVALID_EVIDENCE
            }
            OcspError::UntrustedResponder => Self::IDENTITY_CORE_ERROR_REASON_TRUST_STATUS_FAILURE,
            OcspError::Unavailable => {
                Self::IDENTITY_CORE_ERROR_REASON_CREDENTIAL_STATUS_UNAVAILABLE
            }
        }
    }
}

#[cfg(test)]
#[path = "error_proto_error_tests.rs"]
mod proto_error_tests;
