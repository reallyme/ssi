// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use thiserror::Error;

use reallyme_ssi_proto::generated::proto::reallyme::identity_core::v1::IdentityCoreErrorReason;

/// Errors returned when validating contact delivery messages and frames.
#[derive(Debug, Error)]
pub enum ContactValidationError {
    /// Required input is absent, malformed, inconsistent, or out of bounds.
    #[error("invalid input")]
    InvalidInput,

    /// CBOR decoding failed.
    #[error("serialization error")]
    Serialization,

    /// The contact message has expired.
    #[error("expired")]
    Expired,

    /// The message was not bound to the expected session transcript.
    #[error("session transcript mismatch")]
    SessionTranscriptMismatch,
}

impl From<ContactValidationError> for IdentityCoreErrorReason {
    fn from(reason: ContactValidationError) -> Self {
        match reason {
            ContactValidationError::InvalidInput => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_CONTACT_VALIDATION_INVALID_INPUT
            }
            ContactValidationError::Serialization => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_CONTACT_VALIDATION_SERIALIZATION
            }
            ContactValidationError::Expired => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_CONTACT_VALIDATION_EXPIRED
            }
            ContactValidationError::SessionTranscriptMismatch => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_CONTACT_VALIDATION_SESSION_TRANSCRIPT_MISMATCH
            }
        }
    }
}

#[cfg(test)]
#[path = "error_proto_error_tests.rs"]
mod proto_error_tests;
