// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_ssi_proto::generated::proto::reallyme::identity_core::v1::IdentityCoreErrorReason;
use thiserror::Error;

/// Stable revocation-source failure codes.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum StatusCheckError {
    /// Certificate or credential is explicitly revoked.
    #[error("revoked")]
    Revoked,

    /// Credential is temporarily suspended.
    #[error("suspended")]
    Suspended,

    /// Status evidence is stale.
    #[error("status expired")]
    Expired,

    /// Status evidence is not yet valid.
    #[error("status not yet valid")]
    NotYetValid,

    /// Requested status index is invalid.
    #[error("invalid status index")]
    InvalidIndex,

    /// Status evidence is malformed.
    #[error("invalid status evidence")]
    InvalidList,

    /// Status evidence signature is invalid.
    #[error("invalid status signature")]
    InvalidSignature,

    /// Status evidence could not be obtained or verified by this source.
    #[error("status unavailable")]
    Unavailable,

    /// An authoritative source reported that it does not know this certificate.
    #[error("status unknown")]
    Unknown,

    /// The certificate's advertised status mechanism is unsupported.
    #[error("status mechanism unsupported")]
    Unsupported,
}

/// Stable revocation policy errors.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum RevocationPolicyError {
    /// The evaluation instant cannot be represented as Unix seconds.
    #[error("invalid revocation evaluation time")]
    InvalidEvaluationTime,

    /// No revocation source was configured.
    #[error("no revocation source configured")]
    NoSources,

    /// All configured revocation sources were unavailable.
    #[error("revocation sources unavailable")]
    Unavailable,
}

/// Stable revocation evidence cache errors.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum RevocationCacheError {
    /// Evidence without an expiry bound cannot be cached.
    #[error("revocation evidence has no expiry")]
    MissingExpiry,

    /// Evidence expiry does not follow its fetch time.
    #[error("revocation evidence expiry precedes fetch time")]
    InvalidExpiry,
}

impl From<RevocationCacheError> for IdentityCoreErrorReason {
    fn from(error: RevocationCacheError) -> Self {
        match error {
            RevocationCacheError::MissingExpiry | RevocationCacheError::InvalidExpiry => {
                Self::IDENTITY_CORE_ERROR_REASON_CREDENTIAL_STATUS_INVALID_TIME_WINDOW
            }
        }
    }
}

impl From<StatusCheckError> for IdentityCoreErrorReason {
    fn from(error: StatusCheckError) -> Self {
        match error {
            StatusCheckError::Revoked => Self::IDENTITY_CORE_ERROR_REASON_CREDENTIAL_STATUS_REVOKED,
            StatusCheckError::Suspended => {
                Self::IDENTITY_CORE_ERROR_REASON_CREDENTIAL_STATUS_SUSPENDED
            }
            StatusCheckError::Expired => Self::IDENTITY_CORE_ERROR_REASON_CREDENTIAL_STATUS_EXPIRED,
            StatusCheckError::NotYetValid => {
                Self::IDENTITY_CORE_ERROR_REASON_CREDENTIAL_STATUS_NOT_YET_VALID
            }
            StatusCheckError::InvalidIndex => {
                Self::IDENTITY_CORE_ERROR_REASON_CREDENTIAL_STATUS_INVALID_INDEX
            }
            StatusCheckError::InvalidList => {
                Self::IDENTITY_CORE_ERROR_REASON_CREDENTIAL_STATUS_INVALID_EVIDENCE
            }
            StatusCheckError::InvalidSignature => {
                Self::IDENTITY_CORE_ERROR_REASON_CREDENTIAL_STATUS_INVALID_SIGNATURE
            }
            StatusCheckError::Unavailable => {
                Self::IDENTITY_CORE_ERROR_REASON_CREDENTIAL_STATUS_UNAVAILABLE
            }
            StatusCheckError::Unknown => Self::IDENTITY_CORE_ERROR_REASON_CREDENTIAL_STATUS_UNKNOWN,
            StatusCheckError::Unsupported => {
                Self::IDENTITY_CORE_ERROR_REASON_CREDENTIAL_STATUS_UNSUPPORTED
            }
        }
    }
}

impl From<RevocationPolicyError> for IdentityCoreErrorReason {
    fn from(error: RevocationPolicyError) -> Self {
        match error {
            RevocationPolicyError::InvalidEvaluationTime => {
                Self::IDENTITY_CORE_ERROR_REASON_CREDENTIAL_STATUS_INVALID_TIME_WINDOW
            }
            RevocationPolicyError::NoSources => {
                Self::IDENTITY_CORE_ERROR_REASON_REVOCATION_SOURCE_NOT_CONFIGURED
            }
            RevocationPolicyError::Unavailable => {
                Self::IDENTITY_CORE_ERROR_REASON_REVOCATION_SOURCES_UNAVAILABLE
            }
        }
    }
}
