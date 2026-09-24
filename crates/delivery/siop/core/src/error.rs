// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use thiserror::Error;

use reallyme_ssi_proto::generated::proto::reallyme::identity_core::v1::IdentityCoreErrorReason;

/// Errors returned by SIOP request construction and validation.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum SiopDeliveryError {
    /// Required input is absent, malformed, inconsistent, or out of bounds.
    #[error("invalid input")]
    InvalidInput,

    /// The SIOP request is expired.
    #[error("expired")]
    Expired,
}

impl From<SiopDeliveryError> for IdentityCoreErrorReason {
    fn from(reason: SiopDeliveryError) -> Self {
        match reason {
            SiopDeliveryError::InvalidInput => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_SIOP_DELIVERY_INVALID_INPUT
            }
            SiopDeliveryError::Expired => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_SIOP_DELIVERY_EXPIRED
            }
        }
    }
}

#[cfg(test)]
#[path = "error_proto_error_tests.rs"]
mod proto_error_tests;
