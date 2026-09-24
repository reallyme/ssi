// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_disclosure_policy::VpPolicyError;
use reallyme_ssi_proto::generated::proto::reallyme::identity_core::v1::IdentityCoreErrorReason;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Stable reasons for presentation command validation failures.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Error, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PresentationCommandReason {
    /// Required request, record, or context field is absent.
    #[error("missing presentation field")]
    MissingField,

    /// Nonce, challenge, or audience binding input is empty or malformed.
    #[error("invalid presentation binding")]
    InvalidBinding,

    /// Presentation or request expiry is not in the future.
    #[error("presentation expired")]
    Expired,

    /// Presentation payload shape is not supported by this command.
    #[error("invalid presentation")]
    InvalidPresentation,

    /// A disclosure request or disclosure fact is malformed.
    #[error("invalid presentation disclosure")]
    InvalidDisclosure,
}

/// Errors returned by the protocol-neutral VP API.
///
/// Policy rejections are normally returned as `VpVerificationReport` so callers
/// can display or protocol-map every failure. The strict helper uses this error
/// for consumers that need a `Result<(), _>` shape.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum VpApiError {
    /// The presentation failed one or more policy requirements.
    #[error("presentation rejected by policy")]
    PolicyRejected(Vec<VpPolicyError>),

    /// Presentation command input is malformed.
    #[error("invalid presentation command")]
    InvalidCommand(PresentationCommandReason),
}

impl From<&VpApiError> for IdentityCoreErrorReason {
    fn from(error: &VpApiError) -> Self {
        match error {
            VpApiError::PolicyRejected(_) => {
                Self::IDENTITY_CORE_ERROR_REASON_PRESENTATION_POLICY_NOT_SATISFIED
            }
            VpApiError::InvalidCommand(PresentationCommandReason::InvalidBinding)
            | VpApiError::InvalidCommand(PresentationCommandReason::Expired) => {
                Self::IDENTITY_CORE_ERROR_REASON_PRESENTATION_BINDING_FAILED
            }
            VpApiError::InvalidCommand(PresentationCommandReason::MissingField)
            | VpApiError::InvalidCommand(PresentationCommandReason::InvalidPresentation)
            | VpApiError::InvalidCommand(PresentationCommandReason::InvalidDisclosure) => {
                Self::IDENTITY_CORE_ERROR_REASON_PRESENTATION_INVALID_RESPONSE
            }
        }
    }
}
