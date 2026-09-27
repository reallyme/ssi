// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use thiserror::Error;

use identity_credential_claims_core::ClaimsError;
use reallyme_credential::committed::error::VcError;
use reallyme_ssi_proto::generated::proto::reallyme::identity_core::v1::IdentityCoreErrorReason;

/// Typed failures returned by credential issuance operations.
#[derive(Debug, Error)]
pub enum VcApiError {
    /// The requested credential profile is unknown or unsupported.
    #[error("unsupported or unknown profile")]
    UnsupportedProfile,

    /// The issuer parameters do not satisfy the selected profile.
    #[error("invalid issuer parameters")]
    InvalidIssuer,

    /// The subject parameters do not satisfy the selected profile.
    #[error("invalid subject parameters")]
    InvalidSubject,

    /// The credential validity interval is empty or otherwise invalid.
    #[error("invalid validity window")]
    InvalidValidity,

    /// The credential status reference is invalid.
    #[error("invalid status reference")]
    InvalidStatus,

    /// Claim validation failed against the configured registry.
    #[error("claims registry error: {0:?}")]
    ClaimsRegistry(ClaimsError),

    /// A claim value does not match its declared type.
    #[error("invalid claim value")]
    InvalidClaimValue(ClaimValueErrorReason),

    /// A claim required by the selected profile is absent.
    #[error("missing required claim")]
    MissingRequiredClaim,

    /// The selected profile requires QEAA metadata, but none was supplied.
    #[error("QEAA required but missing")]
    QeaaRequired,

    /// The supplied QEAA metadata is invalid.
    #[error("QEAA provided but invalid")]
    QeaaInvalid,

    /// Credential commitment or signature creation failed.
    #[error("credential issuance failed")]
    IssuanceFailed,

    /// The committed-credential layer rejected the operation.
    #[error("vc-core error: {0}")]
    VcCore(#[from] VcError),

    /// The requested output encoding is unavailable in this build.
    #[error("encoding not enabled (compile-time feature missing)")]
    EncoderNotAvailable,

    /// Public credential encoding failed.
    #[error("encoding failed")]
    EncodingFailed,

    /// Protobuf encoding or decoding failed.
    #[error("proto codec error")]
    ProtoCodec,

    /// Credential compression or decompression failed.
    #[error("compression error")]
    Compression,
}

impl From<ClaimsError> for VcApiError {
    fn from(e: ClaimsError) -> Self {
        VcApiError::ClaimsRegistry(e)
    }
}

/// Expected claim type that an input value failed to satisfy.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum ClaimValueErrorReason {
    /// The registry did not provide a supported claim type.
    #[error("unspecified claim type")]
    Unspecified,

    /// The value is not a JSON string.
    #[error("expected string claim value")]
    ExpectedString,

    /// The value is not a JSON boolean.
    #[error("expected boolean claim value")]
    ExpectedBoolean,

    /// The value is not an integer.
    #[error("expected integer claim value")]
    ExpectedInteger,

    /// The value is not a signed integer.
    #[error("expected signed integer claim value")]
    ExpectedSignedInteger,

    /// The value is not an unsigned integer.
    #[error("expected unsigned integer claim value")]
    ExpectedUnsignedInteger,

    /// The value is not a JSON number.
    #[error("expected number claim value")]
    ExpectedNumber,

    /// The value is not an accepted decimal representation.
    #[error("expected decimal claim value")]
    ExpectedDecimal,

    /// The value is not an encoded byte string.
    #[error("expected bytes claim value")]
    ExpectedBytes,

    /// The value is not an accepted date or date-time string.
    #[error("expected date claim value")]
    ExpectedDate,

    /// The value is not JSON null.
    #[error("expected null claim value")]
    ExpectedNull,

    /// The value is not a JSON object.
    #[error("expected object claim value")]
    ExpectedObject,

    /// The value is not a JSON array.
    #[error("expected array claim value")]
    ExpectedArray,
}

impl From<ClaimValueErrorReason> for IdentityCoreErrorReason {
    fn from(reason: ClaimValueErrorReason) -> Self {
        match reason {
            ClaimValueErrorReason::Unspecified => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_VC_CLAIM_VALUE_UNSPECIFIED
            }
            ClaimValueErrorReason::ExpectedString => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_VC_CLAIM_VALUE_EXPECTED_STRING
            }
            ClaimValueErrorReason::ExpectedBoolean => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_VC_CLAIM_VALUE_EXPECTED_BOOLEAN
            }
            ClaimValueErrorReason::ExpectedInteger => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_VC_CLAIM_VALUE_EXPECTED_INTEGER
            }
            ClaimValueErrorReason::ExpectedSignedInteger => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_VC_CLAIM_VALUE_EXPECTED_SIGNED_INTEGER
            }
            ClaimValueErrorReason::ExpectedUnsignedInteger => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_VC_CLAIM_VALUE_EXPECTED_UNSIGNED_INTEGER
            }
            ClaimValueErrorReason::ExpectedNumber => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_VC_CLAIM_VALUE_EXPECTED_NUMBER
            }
            ClaimValueErrorReason::ExpectedDecimal => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_VC_CLAIM_VALUE_EXPECTED_DECIMAL
            }
            ClaimValueErrorReason::ExpectedBytes => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_VC_CLAIM_VALUE_EXPECTED_BYTES
            }
            ClaimValueErrorReason::ExpectedDate => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_VC_CLAIM_VALUE_EXPECTED_DATE
            }
            ClaimValueErrorReason::ExpectedNull => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_VC_CLAIM_VALUE_EXPECTED_NULL
            }
            ClaimValueErrorReason::ExpectedObject => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_VC_CLAIM_VALUE_EXPECTED_OBJECT
            }
            ClaimValueErrorReason::ExpectedArray => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_VC_CLAIM_VALUE_EXPECTED_ARRAY
            }
        }
    }
}

impl From<VcApiError> for IdentityCoreErrorReason {
    fn from(reason: VcApiError) -> Self {
        match reason {
            VcApiError::UnsupportedProfile => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_VC_API_UNSUPPORTED_PROFILE
            }
            VcApiError::InvalidIssuer => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_VC_API_INVALID_ISSUER
            }
            VcApiError::InvalidSubject => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_VC_API_INVALID_SUBJECT
            }
            VcApiError::InvalidValidity => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_VC_API_INVALID_VALIDITY
            }
            VcApiError::InvalidStatus => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_VC_API_INVALID_STATUS
            }
            VcApiError::ClaimsRegistry(error) => error.into(),
            VcApiError::InvalidClaimValue(reason) => reason.into(),
            VcApiError::MissingRequiredClaim => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_VC_API_MISSING_REQUIRED_CLAIM
            }
            VcApiError::QeaaRequired => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_VC_API_QEAA_REQUIRED
            }
            VcApiError::QeaaInvalid => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_VC_API_QEAA_INVALID
            }
            VcApiError::IssuanceFailed => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_VC_API_ISSUANCE_FAILED
            }
            VcApiError::VcCore(error) => error.into(),
            VcApiError::EncoderNotAvailable => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_VC_API_ENCODER_NOT_AVAILABLE
            }
            VcApiError::EncodingFailed => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_VC_API_ENCODING_FAILED
            }
            VcApiError::ProtoCodec => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_VC_API_PROTO_CODEC
            }
            VcApiError::Compression => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_VC_API_COMPRESSION
            }
        }
    }
}

#[cfg(test)]
#[path = "error_proto_error_tests.rs"]
mod proto_error_tests;
