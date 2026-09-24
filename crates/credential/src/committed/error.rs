// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0
use thiserror::Error;

use reallyme_ssi_proto::generated::proto::reallyme::identity_core::v1::IdentityCoreErrorReason;

#[derive(Debug, Error)]
pub enum VcError {
    /// Canonical CBOR encoding failed.
    #[error("canonicalization failed")]
    Canonicalization,

    /// Invalid credential model.
    #[error("invalid credential")]
    InvalidCredential,

    /// Unsupported or inconsistent credential profile.
    #[error("unsupported credential profile")]
    UnsupportedProfile,

    /// Credential issuance could not obtain acceptable entropy.
    ///
    /// The public message deliberately does not distinguish an unavailable
    /// system RNG from repeated invalid output, because backend details must
    /// not cross the credential boundary.
    #[error("credential issuance failed")]
    EntropyUnavailable,
}

impl From<VcError> for IdentityCoreErrorReason {
    fn from(reason: VcError) -> Self {
        match reason {
            VcError::Canonicalization => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_VC_CANONICALIZATION
            }
            VcError::InvalidCredential => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_VC_INVALID_CREDENTIAL
            }
            VcError::UnsupportedProfile => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_VC_UNSUPPORTED_PROFILE
            }
            VcError::EntropyUnavailable => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_VC_API_ISSUANCE_FAILED
            }
        }
    }
}

#[cfg(test)]
#[path = "error_proto_error_tests.rs"]
mod proto_error_tests;
