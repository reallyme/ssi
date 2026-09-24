// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_ssi_proto::generated::proto::reallyme::identity_core::v1::IdentityCoreErrorReason;
use thiserror::Error;

/// Fixed VP core error categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum VpError {
    /// A presentation does not satisfy the core model invariants.
    #[error("invalid presentation")]
    InvalidPresentation,

    /// A presentation format is not implemented by the selected verifier.
    #[error("unsupported presentation")]
    UnsupportedPresentation,

    /// Cryptographic verification failed without exposing backend details.
    #[error("crypto error")]
    Crypto,

    /// A disclosure request or response is malformed.
    #[error("invalid disclosure")]
    InvalidDisclosure,
}

impl From<VpError> for IdentityCoreErrorReason {
    fn from(error: VpError) -> Self {
        match error {
            VpError::InvalidPresentation => {
                Self::IDENTITY_CORE_ERROR_REASON_PRESENTATION_INVALID_RESPONSE
            }
            VpError::UnsupportedPresentation => Self::IDENTITY_CORE_ERROR_REASON_UNSUPPORTED_FORMAT,
            VpError::Crypto => Self::IDENTITY_CORE_ERROR_REASON_INVALID_SIGNATURE,
            VpError::InvalidDisclosure => {
                Self::IDENTITY_CORE_ERROR_REASON_PRESENTATION_POLICY_NOT_SATISFIED
            }
        }
    }
}
