// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_ssi_proto::generated::proto::reallyme::identity_core::v1::IdentityCoreErrorReason;
use thiserror::Error;

/// Stable reasons for invalid claim registry inputs.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ClaimsInvalidReason {
    /// Claimset identifier is absent.
    #[error("empty claimset id")]
    EmptyClaimsetId,

    /// Claim identifier is absent.
    #[error("empty claim id")]
    EmptyClaimId,

    /// Registry map key does not match the embedded claim identifier.
    #[error("claim key mismatch")]
    ClaimKeyMismatch,

    /// Claim value type is unspecified.
    #[error("invalid claim type")]
    InvalidClaimType,

    /// Claim encoding label is absent.
    #[error("empty claim encoding")]
    EmptyEncoding,

    /// Disclosure mode is unspecified or hidden in a request context.
    #[error("invalid disclosure mode")]
    InvalidDisclosureMode,

    /// Claim path is not canonical.
    #[error("invalid claim path")]
    InvalidClaimPath,

    /// Claim path segment is not canonical.
    #[error("invalid claim path segment")]
    InvalidClaimPathSegment,

    /// Claim path is longer than the registry limit.
    #[error("claim path too long")]
    ClaimPathTooLong,

    /// Claim path nesting exceeds the registry limit.
    #[error("claim path too deep")]
    ClaimPathTooDeep,

    /// Wildcard selectors are not accepted in production claim registries.
    #[error("wildcard claim path not allowed")]
    WildcardClaimPathNotAllowed,

    /// Registry contains claim definitions whose paths overlap.
    #[error("parent child claim path conflict")]
    ParentChildClaimPathConflict,

    /// Credential claim payload root is not an object.
    #[error("claim payload root must be object")]
    ClaimPayloadRootNotObject,

    /// Credential claim payload value does not match its registered type.
    #[error("claim value type mismatch")]
    ClaimValueTypeMismatch,

    /// Claim payload value exceeds an array, object, string, bytes, or depth limit.
    #[error("claim value resource limit exceeded")]
    ClaimValueLimitExceeded,

    /// Decimal claim value is not canonical.
    #[error("invalid decimal claim value")]
    InvalidDecimal,

    /// Date claim value is not a valid ISO 8601 calendar date.
    #[error("invalid date claim value")]
    InvalidDate,

    /// Date-time claim value is not a valid RFC 3339 timestamp.
    #[error("invalid date time claim value")]
    InvalidDateTime,

    /// Claim payload contains the same object member more than once.
    #[error("duplicate claim name")]
    DuplicateClaimName,

    /// Claim payload contains the same canonical path more than once.
    #[error("duplicate claim path")]
    DuplicateClaimPath,

    /// Claim payload contains a non-ASCII claim name that could be confusable.
    #[error("confusable claim name")]
    ConfusableClaimName,

    /// Claim payload JSON could not be parsed into the normalized claim model.
    #[error("invalid claim payload JSON")]
    InvalidClaimPayloadJson,

    /// The registry contains too many claims.
    #[error("too many claims")]
    TooManyClaims,

    /// A claim identifier is longer than the registry limit.
    #[error("claim id too long")]
    ClaimIdTooLong,

    /// A claim definition contains too many predicate modes.
    #[error("too many disclosure predicates")]
    TooManyPredicates,

    /// Claim commitment or opening material has an invalid byte length.
    #[error("invalid commitment material")]
    InvalidCommitmentMaterial,

    /// Claim commitment domain separation tags are absent or oversized.
    #[error("invalid commitment domain tags")]
    InvalidCommitmentDomainTags,

    /// Holder-private claim bundle tree metadata does not match its openings.
    #[error("invalid private bundle tree")]
    InvalidPrivateBundleTree,

    /// Claim commitment uses an unsupported hash algorithm.
    #[error("unsupported commitment hash algorithm")]
    UnsupportedCommitmentHash,

    /// Claim commitment uses an unsupported value encoding.
    #[error("unsupported commitment value encoding")]
    UnsupportedCommitmentEncoding,

    /// Claim opening does not verify against the public Merkle root.
    #[error("invalid commitment proof")]
    InvalidCommitmentProof,
}

/// Claim registry and disclosure validation errors.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ClaimsError {
    /// Registry or claim definition is malformed.
    #[error("invalid claims registry")]
    InvalidInput(ClaimsInvalidReason),

    /// The requested claim does not exist in the registry.
    #[error("unknown claim")]
    UnknownClaim,

    /// Direct value reveal is not permitted.
    #[error("claim reveal not allowed")]
    DisclosureNotAllowed,

    /// Requested predicate mode is not permitted.
    #[error("claim predicate not allowed")]
    PredicateNotAllowed,
}

impl From<ClaimsInvalidReason> for IdentityCoreErrorReason {
    fn from(reason: ClaimsInvalidReason) -> Self {
        match reason {
            ClaimsInvalidReason::EmptyClaimsetId => {
                Self::IDENTITY_CORE_ERROR_REASON_CLAIMS_EMPTY_CLAIMSET_ID
            }
            ClaimsInvalidReason::EmptyClaimId => {
                Self::IDENTITY_CORE_ERROR_REASON_CLAIMS_EMPTY_CLAIM_ID
            }
            ClaimsInvalidReason::ClaimKeyMismatch => {
                Self::IDENTITY_CORE_ERROR_REASON_CLAIMS_CLAIM_KEY_MISMATCH
            }
            ClaimsInvalidReason::InvalidClaimType => {
                Self::IDENTITY_CORE_ERROR_REASON_CLAIMS_INVALID_CLAIM_TYPE
            }
            ClaimsInvalidReason::EmptyEncoding => {
                Self::IDENTITY_CORE_ERROR_REASON_CLAIMS_EMPTY_ENCODING
            }
            ClaimsInvalidReason::InvalidDisclosureMode => {
                Self::IDENTITY_CORE_ERROR_REASON_CLAIMS_INVALID_DISCLOSURE_MODE
            }
            ClaimsInvalidReason::InvalidClaimPath => {
                Self::IDENTITY_CORE_ERROR_REASON_CLAIMS_INVALID_CLAIM_PATH
            }
            ClaimsInvalidReason::InvalidClaimPathSegment => {
                Self::IDENTITY_CORE_ERROR_REASON_CLAIMS_INVALID_CLAIM_PATH_SEGMENT
            }
            ClaimsInvalidReason::ClaimPathTooLong => {
                Self::IDENTITY_CORE_ERROR_REASON_CLAIMS_CLAIM_PATH_TOO_LONG
            }
            ClaimsInvalidReason::ClaimPathTooDeep => {
                Self::IDENTITY_CORE_ERROR_REASON_CLAIMS_CLAIM_PATH_TOO_DEEP
            }
            ClaimsInvalidReason::WildcardClaimPathNotAllowed => {
                Self::IDENTITY_CORE_ERROR_REASON_CLAIMS_WILDCARD_CLAIM_PATH_NOT_ALLOWED
            }
            ClaimsInvalidReason::ParentChildClaimPathConflict => {
                Self::IDENTITY_CORE_ERROR_REASON_CLAIMS_PARENT_CHILD_CLAIM_PATH_CONFLICT
            }
            ClaimsInvalidReason::ClaimPayloadRootNotObject => {
                Self::IDENTITY_CORE_ERROR_REASON_CLAIMS_PAYLOAD_ROOT_NOT_OBJECT
            }
            ClaimsInvalidReason::ClaimValueTypeMismatch => {
                Self::IDENTITY_CORE_ERROR_REASON_CLAIMS_VALUE_TYPE_MISMATCH
            }
            ClaimsInvalidReason::ClaimValueLimitExceeded => {
                Self::IDENTITY_CORE_ERROR_REASON_CLAIMS_VALUE_LIMIT_EXCEEDED
            }
            ClaimsInvalidReason::InvalidDecimal => {
                Self::IDENTITY_CORE_ERROR_REASON_CLAIMS_INVALID_DECIMAL
            }
            ClaimsInvalidReason::InvalidDate => {
                Self::IDENTITY_CORE_ERROR_REASON_CLAIMS_INVALID_DATE
            }
            ClaimsInvalidReason::InvalidDateTime => {
                Self::IDENTITY_CORE_ERROR_REASON_CLAIMS_INVALID_DATE_TIME
            }
            ClaimsInvalidReason::DuplicateClaimName => {
                Self::IDENTITY_CORE_ERROR_REASON_CLAIMS_DUPLICATE_CLAIM_NAME
            }
            ClaimsInvalidReason::DuplicateClaimPath => {
                Self::IDENTITY_CORE_ERROR_REASON_CLAIMS_DUPLICATE_CLAIM_PATH
            }
            ClaimsInvalidReason::ConfusableClaimName => {
                Self::IDENTITY_CORE_ERROR_REASON_CLAIMS_CONFUSABLE_CLAIM_NAME
            }
            ClaimsInvalidReason::InvalidClaimPayloadJson => {
                Self::IDENTITY_CORE_ERROR_REASON_CLAIMS_INVALID_PAYLOAD_JSON
            }
            ClaimsInvalidReason::TooManyClaims => {
                Self::IDENTITY_CORE_ERROR_REASON_CLAIMS_TOO_MANY_CLAIMS
            }
            ClaimsInvalidReason::ClaimIdTooLong => {
                Self::IDENTITY_CORE_ERROR_REASON_CLAIMS_CLAIM_ID_TOO_LONG
            }
            ClaimsInvalidReason::TooManyPredicates => {
                Self::IDENTITY_CORE_ERROR_REASON_CLAIMS_TOO_MANY_PREDICATES
            }
            ClaimsInvalidReason::InvalidCommitmentMaterial => {
                Self::IDENTITY_CORE_ERROR_REASON_CLAIMS_INVALID_COMMITMENT_MATERIAL
            }
            ClaimsInvalidReason::InvalidCommitmentDomainTags => {
                Self::IDENTITY_CORE_ERROR_REASON_CLAIMS_INVALID_COMMITMENT_DOMAIN_TAGS
            }
            ClaimsInvalidReason::InvalidPrivateBundleTree => {
                Self::IDENTITY_CORE_ERROR_REASON_CLAIMS_INVALID_PRIVATE_BUNDLE_TREE
            }
            ClaimsInvalidReason::UnsupportedCommitmentHash => {
                Self::IDENTITY_CORE_ERROR_REASON_CLAIMS_UNSUPPORTED_COMMITMENT_HASH
            }
            ClaimsInvalidReason::UnsupportedCommitmentEncoding => {
                Self::IDENTITY_CORE_ERROR_REASON_CLAIMS_UNSUPPORTED_COMMITMENT_ENCODING
            }
            ClaimsInvalidReason::InvalidCommitmentProof => {
                Self::IDENTITY_CORE_ERROR_REASON_CLAIMS_INVALID_COMMITMENT_PROOF
            }
        }
    }
}

impl From<ClaimsError> for IdentityCoreErrorReason {
    fn from(error: ClaimsError) -> Self {
        match error {
            ClaimsError::InvalidInput(reason) => reason.into(),
            ClaimsError::UnknownClaim => Self::IDENTITY_CORE_ERROR_REASON_CLAIMS_UNKNOWN_CLAIM,
            ClaimsError::DisclosureNotAllowed => {
                Self::IDENTITY_CORE_ERROR_REASON_CLAIMS_DISCLOSURE_NOT_ALLOWED
            }
            ClaimsError::PredicateNotAllowed => {
                Self::IDENTITY_CORE_ERROR_REASON_CLAIMS_PREDICATE_NOT_ALLOWED
            }
        }
    }
}

#[cfg(test)]
#[path = "error_proto_error_tests.rs"]
mod proto_error_tests;
