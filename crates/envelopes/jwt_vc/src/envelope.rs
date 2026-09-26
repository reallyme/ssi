// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use thiserror::Error;

use reallyme_ssi_proto::generated::proto::reallyme::identity_core::v1::IdentityCoreErrorReason;

/// JWT-VC claim validation entry points.
#[path = "claims.rs"]
pub mod claims;
/// JWT-VC issuance entry points.
#[path = "issue.rs"]
pub mod issue;
/// JWT-VC temporal claim validation against the verifier's clock.
#[path = "validate_temporal.rs"]
mod validate_temporal;
/// JWT-VC verification entry points.
#[path = "verify.rs"]
pub mod verify;

pub use claims::{validate_jwt_vc_claims, JwtVcPayload};
pub use issue::{issue_jwt_vc, issue_jwt_vc_with_signer, JwtVcIssueInput};
pub use validate_temporal::MAX_JWT_VC_CLOCK_SKEW_SECONDS;
pub use verify::{verify_jwt_vc, JwtVcVerificationOptions, VerifiedJwtVc};

/// Current implementation status for JWT-VC envelope support.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JwtVcEnvelopeStatus {
    /// JWT-VC issue and verify paths are available for canonical credential
    /// bytes and optional protobuf transport bytes.
    Implemented,
}

/// Error for JWT-VC envelope operations.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum JwtVcEnvelopeError {
    /// Required JWT-VC input was absent or empty.
    #[error("invalid JWT-VC input")]
    InvalidInput,

    /// Decoded JWT-VC claims are structurally invalid.
    #[error("invalid JWT-VC payload")]
    InvalidPayload,

    /// Base64url-encoded credential bytes could not be decoded.
    #[error("invalid JWT-VC credential encoding")]
    InvalidCredentialEncoding,

    /// JOSE signing or verification failed.
    #[error("JWT-VC JOSE operation failed")]
    Jwt,

    /// Verification options carried a zero or otherwise invalid current time,
    /// or a clock skew above the supported maximum.
    #[error("invalid JWT-VC verification time")]
    InvalidVerificationTime,

    /// A temporal claim is not a non-negative NumericDate or `iat` lies in
    /// the future beyond the tolerated clock skew.
    #[error("invalid JWT-VC temporal claim")]
    InvalidTemporalClaim,

    /// The credential `exp` claim is at or before the verification time.
    #[error("JWT-VC credential expired")]
    CredentialExpired,

    /// The credential `nbf` claim is after the verification time.
    #[error("JWT-VC credential not yet valid")]
    CredentialNotYetValid,
}

impl From<JwtVcEnvelopeError> for IdentityCoreErrorReason {
    fn from(reason: JwtVcEnvelopeError) -> Self {
        match reason {
            JwtVcEnvelopeError::InvalidInput | JwtVcEnvelopeError::InvalidVerificationTime => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_JWT_VC_ENVELOPE_INVALID_INPUT
            }
            JwtVcEnvelopeError::InvalidPayload
            | JwtVcEnvelopeError::InvalidTemporalClaim
            | JwtVcEnvelopeError::CredentialExpired
            | JwtVcEnvelopeError::CredentialNotYetValid => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_JWT_VC_ENVELOPE_INVALID_PAYLOAD
            }
            JwtVcEnvelopeError::InvalidCredentialEncoding => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_JWT_VC_ENVELOPE_INVALID_CREDENTIAL_ENCODING
            }
            JwtVcEnvelopeError::Jwt => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_JWT_VC_ENVELOPE_JWT
            }
        }
    }
}

/// Return the current implementation status for the JWT-VC envelope family.
pub const fn jwt_vc_envelope_status() -> JwtVcEnvelopeStatus {
    JwtVcEnvelopeStatus::Implemented
}

impl From<reallyme_codec::base64url::Base64UrlError> for JwtVcEnvelopeError {
    fn from(_: reallyme_codec::base64url::Base64UrlError) -> Self {
        JwtVcEnvelopeError::InvalidCredentialEncoding
    }
}

impl From<reallyme_jose::jwt::JwtError> for JwtVcEnvelopeError {
    fn from(_: reallyme_jose::jwt::JwtError) -> Self {
        JwtVcEnvelopeError::Jwt
    }
}

#[cfg(test)]
#[path = "lib_proto_error_tests.rs"]
mod proto_error_tests;
