// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_ssi_proto::generated::proto::reallyme::identity_core::v1::IdentityCoreErrorReason;
use thiserror::Error;

/// Errors that can occur while applying an authorized DID core update.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum UpdateError {
    /// The proposed document sequence does not advance exactly once.
    #[error("invalid update sequence")]
    InvalidSequence,

    /// The proposed `prev` CID does not point at the previous core.
    #[error("prev CID does not match previous document")]
    InvalidPrev,

    /// Rotating a verification method required key material that was not provided.
    #[error("missing rotated key material")]
    MissingRotatedKey,

    /// A rotation request referenced a verification method outside the document.
    #[error("unknown verification method")]
    UnknownVerificationMethod,

    /// The resulting DID Document does not satisfy a required algorithm profile.
    #[error("required algorithm not satisfied")]
    UnsatisfiedRequiredAlgorithm,

    /// A domain-verification entry is malformed after update.
    #[error("invalid domain verification entry")]
    InvalidDomainVerification,

    /// The update policy rejects the requested update.
    #[error("update policy violation")]
    PolicyViolation,

    /// The proposed state is internally inconsistent.
    #[error("invalid update state")]
    InvalidState,
}

impl From<UpdateError> for IdentityCoreErrorReason {
    fn from(error: UpdateError) -> Self {
        match error {
            UpdateError::PolicyViolation => Self::IDENTITY_CORE_ERROR_REASON_POLICY_VIOLATION,
            UpdateError::UnknownVerificationMethod => {
                Self::IDENTITY_CORE_ERROR_REASON_DID_INVALID_VERIFICATION_METHOD
            }
            UpdateError::UnsatisfiedRequiredAlgorithm => {
                Self::IDENTITY_CORE_ERROR_REASON_UNSUPPORTED_ALGORITHM
            }
            UpdateError::InvalidDomainVerification => {
                Self::IDENTITY_CORE_ERROR_REASON_DID_INVALID_DOCUMENT
            }
            _ => Self::IDENTITY_CORE_ERROR_REASON_DID_INVALID_UPDATE_POLICY,
        }
    }
}
