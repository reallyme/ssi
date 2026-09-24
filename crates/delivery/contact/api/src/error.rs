// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use thiserror::Error;

use identity_presentation_delivery_contact_core::ContactDeliveryError;
use identity_presentation_delivery_contact_validator::ContactValidationError;
use reallyme_ssi_proto::generated::proto::reallyme::identity_core::v1::IdentityCoreErrorReason;

/// Errors returned by the contact delivery API facade.
#[derive(Debug, Error)]
pub enum ContactApiError {
    /// Required input is absent, malformed, inconsistent, or out of bounds.
    #[error("invalid input")]
    InvalidInput,

    /// CBOR encoding or decoding failed.
    #[error("serialization error")]
    Serialization,

    /// The contact message has expired.
    #[error("expired")]
    Expired,

    /// The message was not bound to the expected session transcript.
    #[error("session transcript mismatch")]
    SessionTranscriptMismatch,
}

impl From<ContactDeliveryError> for ContactApiError {
    fn from(e: ContactDeliveryError) -> Self {
        match e {
            ContactDeliveryError::InvalidInput => ContactApiError::InvalidInput,
            ContactDeliveryError::Serialization => ContactApiError::Serialization,
            ContactDeliveryError::MessageTooLarge => ContactApiError::InvalidInput,
            ContactDeliveryError::FrameTooLarge => ContactApiError::InvalidInput,
            ContactDeliveryError::TooManyFrames => ContactApiError::InvalidInput,
        }
    }
}

impl From<ContactValidationError> for ContactApiError {
    fn from(e: ContactValidationError) -> Self {
        match e {
            ContactValidationError::InvalidInput => ContactApiError::InvalidInput,
            ContactValidationError::Serialization => ContactApiError::Serialization,
            ContactValidationError::Expired => ContactApiError::Expired,
            ContactValidationError::SessionTranscriptMismatch => {
                ContactApiError::SessionTranscriptMismatch
            }
        }
    }
}

impl From<ContactApiError> for IdentityCoreErrorReason {
    fn from(reason: ContactApiError) -> Self {
        match reason {
            ContactApiError::InvalidInput => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_CONTACT_API_INVALID_INPUT
            }
            ContactApiError::Serialization => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_CONTACT_API_SERIALIZATION
            }
            ContactApiError::Expired => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_CONTACT_API_EXPIRED
            }
            ContactApiError::SessionTranscriptMismatch => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_CONTACT_API_SESSION_TRANSCRIPT_MISMATCH
            }
        }
    }
}

#[cfg(test)]
#[path = "error_proto_error_tests.rs"]
mod proto_error_tests;
