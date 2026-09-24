// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_ssi_proto::generated::proto::reallyme::identity_core::v1::IdentityCoreErrorReason;
use thiserror::Error;

/// Typed failures from the OpenSSL OCSP backend.
#[derive(Debug, Error)]
pub enum OcspOpenSslError {
    /// OCSP response DER could not be parsed.
    #[error("invalid OCSP response DER")]
    InvalidDer,

    /// OCSP response status was not successful.
    #[error("OCSP response status not successful")]
    ResponseNotSuccessful,

    /// OCSP basic response was missing.
    #[error("OCSP basic response missing")]
    MissingBasic,

    /// OCSP response signature verification failed.
    #[error("OCSP signature verification failed")]
    BadSignature,

    /// No single response matched the requested certificate.
    #[error("OCSP status for certificate not found in response")]
    NoMatchingSingleResponse,

    /// OCSP response contained an invalid time field.
    #[error("invalid time in OCSP response")]
    InvalidTime,

    /// OpenSSL backend failed without exposing backend internals.
    #[error("openssl backend error")]
    Backend,
}

impl From<OcspOpenSslError> for IdentityCoreErrorReason {
    fn from(error: OcspOpenSslError) -> Self {
        match error {
            OcspOpenSslError::InvalidDer
            | OcspOpenSslError::ResponseNotSuccessful
            | OcspOpenSslError::MissingBasic
            | OcspOpenSslError::NoMatchingSingleResponse => {
                Self::IDENTITY_CORE_ERROR_REASON_CREDENTIAL_STATUS_INVALID_EVIDENCE
            }
            OcspOpenSslError::BadSignature => {
                Self::IDENTITY_CORE_ERROR_REASON_CREDENTIAL_STATUS_INVALID_SIGNATURE
            }
            OcspOpenSslError::InvalidTime => {
                Self::IDENTITY_CORE_ERROR_REASON_CREDENTIAL_STATUS_INVALID_TIME_WINDOW
            }
            OcspOpenSslError::Backend => {
                Self::IDENTITY_CORE_ERROR_REASON_CREDENTIAL_STATUS_UNAVAILABLE
            }
        }
    }
}

#[cfg(test)]
#[path = "error_proto_error_tests.rs"]
mod proto_error_tests;
