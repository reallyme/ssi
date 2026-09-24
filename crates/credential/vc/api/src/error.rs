// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use thiserror::Error;

use identity_credential_claims_core::ClaimsError;
use reallyme_credential::committed::error::VcError;
use reallyme_ssi_proto::generated::proto::reallyme::identity_core::v1::IdentityCoreErrorReason;

#[derive(Debug, Error)]
pub enum VcApiError {
    // --------------------------------------------------
    // Profile / input validation
    // --------------------------------------------------
    #[error("unsupported or unknown profile")]
    UnsupportedProfile,

    #[error("invalid issuer parameters")]
    InvalidIssuer,

    #[error("invalid subject parameters")]
    InvalidSubject,

    #[error("invalid validity window")]
    InvalidValidity,

    #[error("invalid status reference")]
    InvalidStatus,

    #[error("claims registry error: {0:?}")]
    ClaimsRegistry(ClaimsError),

    #[error("invalid claim value")]
    InvalidClaimValue(ClaimValueErrorReason),

    #[error("missing required claim")]
    MissingRequiredClaim,

    // --------------------------------------------------
    // QEAA
    // --------------------------------------------------
    #[error("QEAA required but missing")]
    QeaaRequired,

    #[error("QEAA provided but invalid")]
    QeaaInvalid,

    // --------------------------------------------------
    // Issuance
    // --------------------------------------------------
    #[error("credential issuance failed")]
    IssuanceFailed,

    #[error("vc-core error: {0}")]
    VcCore(#[from] VcError),

    // --------------------------------------------------
    // Encoding / transport
    // --------------------------------------------------
    #[error("encoding not enabled (compile-time feature missing)")]
    EncoderNotAvailable,

    #[error("encoding failed")]
    EncodingFailed,

    #[error("proto codec error")]
    ProtoCodec,

    #[error("compression error")]
    Compression,
}

impl From<ClaimsError> for VcApiError {
    fn from(e: ClaimsError) -> Self {
        VcApiError::ClaimsRegistry(e)
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum ClaimValueErrorReason {
    #[error("unspecified claim type")]
    Unspecified,

    #[error("expected string claim value")]
    ExpectedString,

    #[error("expected boolean claim value")]
    ExpectedBoolean,

    #[error("expected integer claim value")]
    ExpectedInteger,

    #[error("expected signed integer claim value")]
    ExpectedSignedInteger,

    #[error("expected unsigned integer claim value")]
    ExpectedUnsignedInteger,

    #[error("expected number claim value")]
    ExpectedNumber,

    #[error("expected decimal claim value")]
    ExpectedDecimal,

    #[error("expected bytes claim value")]
    ExpectedBytes,

    #[error("expected date claim value")]
    ExpectedDate,

    #[error("expected null claim value")]
    ExpectedNull,

    #[error("expected object claim value")]
    ExpectedObject,

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
