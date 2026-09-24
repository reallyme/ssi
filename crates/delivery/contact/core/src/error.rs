// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use thiserror::Error;

use reallyme_ssi_proto::generated::proto::reallyme::identity_core::v1::IdentityCoreErrorReason;

/// Errors returned by contact message construction and frame reassembly.
#[derive(Debug, Error)]
pub enum ContactDeliveryError {
    /// Required input is absent, malformed, inconsistent, or out of bounds.
    #[error("invalid input")]
    InvalidInput,

    /// CBOR encoding or decoding failed.
    #[error("serialization error")]
    Serialization,

    /// The complete message exceeds the configured message ceiling.
    #[error("message too large")]
    MessageTooLarge,

    /// A single frame exceeds the configured frame ceiling.
    #[error("frame too large")]
    FrameTooLarge,

    /// The message would require more frames than the configured ceiling.
    #[error("too many frames")]
    TooManyFrames,
}

impl From<ContactDeliveryError> for IdentityCoreErrorReason {
    fn from(reason: ContactDeliveryError) -> Self {
        match reason {
            ContactDeliveryError::InvalidInput => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_CONTACT_DELIVERY_INVALID_INPUT
            }
            ContactDeliveryError::Serialization => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_CONTACT_DELIVERY_SERIALIZATION
            }
            ContactDeliveryError::MessageTooLarge => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_CONTACT_DELIVERY_MESSAGE_TOO_LARGE
            }
            ContactDeliveryError::FrameTooLarge => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_CONTACT_DELIVERY_FRAME_TOO_LARGE
            }
            ContactDeliveryError::TooManyFrames => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_CONTACT_DELIVERY_TOO_MANY_FRAMES
            }
        }
    }
}

#[cfg(test)]
#[path = "error_proto_error_tests.rs"]
mod proto_error_tests;
