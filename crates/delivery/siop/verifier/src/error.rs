// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use thiserror::Error;

use reallyme_ssi_proto::generated::proto::reallyme::identity_core::v1::IdentityCoreErrorReason;

/// Errors returned by SIOP ID token verification.
#[derive(Debug, Error)]
pub enum SiopVerifierError {
    /// Required input is absent, malformed, inconsistent, or unsupported.
    #[error("invalid input")]
    InvalidInput,

    /// JWT signature verification failed.
    #[error("invalid signature")]
    InvalidSignature,

    /// The request or ID token has expired.
    #[error("expired")]
    Expired,

    /// The ID token audience does not match the originating request.
    #[error("audience mismatch")]
    AudienceMismatch,

    /// The ID token nonce does not match the originating request.
    #[error("nonce mismatch")]
    NonceMismatch,
}

impl From<SiopVerifierError> for IdentityCoreErrorReason {
    fn from(reason: SiopVerifierError) -> Self {
        match reason {
            SiopVerifierError::InvalidInput => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_SIOP_VERIFIER_INVALID_INPUT
            }
            SiopVerifierError::InvalidSignature => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_SIOP_VERIFIER_INVALID_SIGNATURE
            }
            SiopVerifierError::Expired => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_SIOP_VERIFIER_EXPIRED
            }
            SiopVerifierError::AudienceMismatch => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_SIOP_VERIFIER_AUDIENCE_MISMATCH
            }
            SiopVerifierError::NonceMismatch => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_SIOP_VERIFIER_NONCE_MISMATCH
            }
        }
    }
}

#[cfg(test)]
#[path = "error_proto_error_tests.rs"]
mod proto_error_tests;
