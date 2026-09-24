// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use identity_presentation_delivery_core::DeliveryError;
use reallyme_ssi_proto::generated::proto::reallyme::identity_core::v1::IdentityCoreErrorReason;
use thiserror::Error;

/// Web delivery failures.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum WebDeliveryError {
    /// Transport-neutral delivery validation failed.
    #[error("delivery error: {0}")]
    Delivery(#[from] DeliveryError),

    /// URL construction or parsing failed.
    #[error("invalid url")]
    InvalidUrl,

    /// Serialization failed for the payload being encoded.
    #[error("serialization error")]
    Serialization,

    /// Signing failed at the injected signer boundary.
    #[error("signing failed")]
    SigningFailed,

    /// Payload variant is not supported by this operation.
    #[error("unsupported payload for this operation")]
    UnsupportedPayload,

    /// Payload shape failed validation.
    #[error("invalid payload")]
    InvalidPayload,
}

impl From<WebDeliveryError> for IdentityCoreErrorReason {
    fn from(reason: WebDeliveryError) -> Self {
        match reason {
            WebDeliveryError::Delivery(delivery_error) => delivery_error.into(),
            WebDeliveryError::InvalidUrl => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_WEB_DELIVERY_INVALID_URL
            }
            WebDeliveryError::Serialization => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_WEB_DELIVERY_SERIALIZATION
            }
            WebDeliveryError::SigningFailed => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_WEB_DELIVERY_SIGNING_FAILED
            }
            WebDeliveryError::UnsupportedPayload => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_WEB_DELIVERY_UNSUPPORTED_PAYLOAD
            }
            WebDeliveryError::InvalidPayload => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_WEB_DELIVERY_INVALID_PAYLOAD
            }
        }
    }
}

#[cfg(test)]
#[path = "error_proto_error_tests.rs"]
mod proto_error_tests;
