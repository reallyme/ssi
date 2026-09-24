// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_ssi_proto::generated::proto::reallyme::identity_core::v1::IdentityCoreErrorReason;
use thiserror::Error;

/// Stable reason codes for invalid credential status-list inputs.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum CredentialStatusInvalidReason {
    /// The status-list issuer identifier is absent.
    #[error("empty status-list issuer")]
    EmptyIssuer,

    /// The status-list length is zero or cannot be represented safely.
    #[error("invalid status-list length")]
    InvalidLength,

    /// The status-list length is above the accepted local validation limit.
    #[error("status-list too large")]
    TooLarge,

    /// The encoded bitstring cannot contain the declared number of entries.
    #[error("invalid status-list encoded bytes")]
    InvalidEncodedList,

    /// The status-list issued/next-update window is absent or not ordered.
    #[error("invalid status-list time window")]
    InvalidTimeWindow,

    /// The status purpose is not supported for credential status checks.
    #[error("unsupported status purpose")]
    UnsupportedPurpose,

    /// The requested credential status index is outside the list bounds.
    #[error("invalid credential status index")]
    InvalidIndex,

    /// The status-list signature is absent or uses an unsupported algorithm.
    #[error("invalid status-list signature")]
    InvalidSignatureMetadata,

    /// The status-list payload could not be encoded deterministically.
    #[error("status-list payload encoding failed")]
    PayloadEncoding,
}

/// Credential status-list verification errors.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum CredentialStatusError {
    /// Input status-list data was structurally invalid.
    #[error("invalid credential status input")]
    InvalidInput(CredentialStatusInvalidReason),

    /// Credential has been revoked.
    #[error("credential revoked")]
    Revoked,

    /// Credential has been suspended.
    #[error("credential suspended")]
    Suspended,

    /// Status-list evidence is stale at the supplied verification time.
    #[error("credential status list expired")]
    Expired,

    /// Status-list evidence is not yet valid at the supplied verification time.
    #[error("credential status list not yet valid")]
    NotYetValid,

    /// Status-list signature verification failed.
    #[error("credential status signature invalid")]
    InvalidSignature,
}

impl From<CredentialStatusInvalidReason> for IdentityCoreErrorReason {
    fn from(reason: CredentialStatusInvalidReason) -> Self {
        match reason {
            CredentialStatusInvalidReason::EmptyIssuer => {
                Self::IDENTITY_CORE_ERROR_REASON_CREDENTIAL_STATUS_EMPTY_ISSUER
            }
            CredentialStatusInvalidReason::InvalidLength => {
                Self::IDENTITY_CORE_ERROR_REASON_CREDENTIAL_STATUS_INVALID_LENGTH
            }
            CredentialStatusInvalidReason::TooLarge => {
                Self::IDENTITY_CORE_ERROR_REASON_CREDENTIAL_STATUS_TOO_LARGE
            }
            CredentialStatusInvalidReason::InvalidEncodedList => {
                Self::IDENTITY_CORE_ERROR_REASON_CREDENTIAL_STATUS_INVALID_ENCODED_LIST
            }
            CredentialStatusInvalidReason::InvalidTimeWindow => {
                Self::IDENTITY_CORE_ERROR_REASON_CREDENTIAL_STATUS_INVALID_TIME_WINDOW
            }
            CredentialStatusInvalidReason::UnsupportedPurpose => {
                Self::IDENTITY_CORE_ERROR_REASON_CREDENTIAL_STATUS_UNSUPPORTED_PURPOSE
            }
            CredentialStatusInvalidReason::InvalidIndex => {
                Self::IDENTITY_CORE_ERROR_REASON_CREDENTIAL_STATUS_INVALID_INDEX
            }
            CredentialStatusInvalidReason::InvalidSignatureMetadata => {
                Self::IDENTITY_CORE_ERROR_REASON_CREDENTIAL_STATUS_INVALID_SIGNATURE_METADATA
            }
            CredentialStatusInvalidReason::PayloadEncoding => {
                Self::IDENTITY_CORE_ERROR_REASON_CREDENTIAL_STATUS_PAYLOAD_ENCODING
            }
        }
    }
}

impl From<CredentialStatusError> for IdentityCoreErrorReason {
    fn from(error: CredentialStatusError) -> Self {
        match error {
            CredentialStatusError::InvalidInput(reason) => reason.into(),
            CredentialStatusError::InvalidSignature => {
                Self::IDENTITY_CORE_ERROR_REASON_CREDENTIAL_STATUS_INVALID_SIGNATURE
            }
            CredentialStatusError::Revoked => {
                Self::IDENTITY_CORE_ERROR_REASON_CREDENTIAL_STATUS_REVOKED
            }
            CredentialStatusError::Suspended => {
                Self::IDENTITY_CORE_ERROR_REASON_CREDENTIAL_STATUS_SUSPENDED
            }
            CredentialStatusError::Expired => {
                Self::IDENTITY_CORE_ERROR_REASON_CREDENTIAL_STATUS_EXPIRED
            }
            CredentialStatusError::NotYetValid => {
                Self::IDENTITY_CORE_ERROR_REASON_CREDENTIAL_STATUS_NOT_YET_VALID
            }
        }
    }
}

#[cfg(test)]
#[path = "error_proto_error_tests.rs"]
mod proto_error_tests;
