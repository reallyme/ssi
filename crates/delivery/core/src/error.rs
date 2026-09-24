// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use thiserror::Error;

use reallyme_ssi_proto::generated::proto::reallyme::identity_core::v1::IdentityCoreErrorReason;

/// Errors related to delivery packaging and constraints.
///
/// These errors are **not** cryptographic and **not** policy-related.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum DeliveryError {
    /// The payload is empty or malformed.
    #[error("invalid delivery payload")]
    InvalidPayload,

    /// The delivery target is not supported.
    #[error("unsupported delivery target")]
    UnsupportedTarget,

    /// The delivery intent is not allowed for this payload.
    #[error("invalid delivery intent")]
    InvalidIntent,

    /// Payload exceeds size limits for the intended channel.
    #[error("payload too large")]
    PayloadTooLarge,

    /// Delivery has expired.
    #[error("delivery expired")]
    Expired,
}

impl From<DeliveryError> for IdentityCoreErrorReason {
    fn from(reason: DeliveryError) -> Self {
        match reason {
            DeliveryError::InvalidPayload => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_DELIVERY_INVALID_PAYLOAD
            }
            DeliveryError::UnsupportedTarget => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_DELIVERY_UNSUPPORTED_TARGET
            }
            DeliveryError::InvalidIntent => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_DELIVERY_INVALID_INTENT
            }
            DeliveryError::PayloadTooLarge => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_DELIVERY_PAYLOAD_TOO_LARGE
            }
            DeliveryError::Expired => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_DELIVERY_EXPIRED
            }
        }
    }
}

#[cfg(test)]
#[path = "error_proto_error_tests.rs"]
mod proto_error_tests;
