// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use thiserror::Error;

use reallyme_ssi_proto::generated::proto::reallyme::identity_core::v1::IdentityCoreErrorReason;

#[derive(Debug, Error)]
pub enum VcJwtError {
    #[error("jwt error")]
    Jwt,

    #[error("invalid vc-jwt payload")]
    InvalidPayload,

    #[error("base64url error")]
    Base64Url,

    #[error("vc core error")]
    VcCore,

    #[error("missing field")]
    MissingField,

    /// Verification options carried a zero or otherwise invalid current time,
    /// or a clock skew above the supported maximum.
    #[error("invalid vc-jwt verification time")]
    InvalidVerificationTime,

    /// A temporal claim is not a non-negative NumericDate, `exp` does not
    /// follow `nbf`, or `iat` lies in the future beyond the tolerated skew.
    #[error("invalid vc-jwt temporal claim")]
    InvalidTemporalClaim,

    /// The credential `exp` claim is at or before the verification time.
    #[error("vc-jwt credential expired")]
    CredentialExpired,

    /// The credential `nbf` claim is after the verification time.
    #[error("vc-jwt credential not yet valid")]
    CredentialNotYetValid,
}

impl From<VcJwtError> for IdentityCoreErrorReason {
    fn from(reason: VcJwtError) -> Self {
        match reason {
            VcJwtError::Jwt => IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_VC_JWT_JWT,
            VcJwtError::InvalidPayload
            | VcJwtError::InvalidVerificationTime
            | VcJwtError::InvalidTemporalClaim
            | VcJwtError::CredentialExpired
            | VcJwtError::CredentialNotYetValid => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_VC_JWT_INVALID_PAYLOAD
            }
            VcJwtError::Base64Url => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_VC_JWT_BASE64URL
            }
            VcJwtError::VcCore => IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_VC_JWT_CORE,
            VcJwtError::MissingField => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_VC_JWT_MISSING_FIELD
            }
        }
    }
}

#[cfg(test)]
#[path = "error_proto_error_tests.rs"]
mod proto_error_tests;
