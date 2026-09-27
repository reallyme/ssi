// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_codec::base64url::Base64UrlError;
use reallyme_crypto::core::CryptoError;
use reallyme_crypto::dispatch::AlgorithmError;
use reallyme_ssi_proto::generated::proto::reallyme::identity_core::v1::IdentityCoreErrorReason;
use thiserror::Error;

/// Typed failures returned by SD-JWT operations.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum SdJwtEnvelopeError {
    /// The compact serialization is malformed or ambiguous.
    #[error("invalid SD-JWT compact serialization")]
    InvalidCompactSerialization,

    /// The JWS JSON serialization is malformed or ambiguous.
    #[error("invalid SD-JWT JWS JSON serialization")]
    InvalidJsonSerialization,

    /// The issuer-signed JWT is malformed or fails validation.
    #[error("invalid issuer-signed JWT component")]
    InvalidIssuerJwt,

    /// The holder key-binding JWT is malformed or fails validation.
    #[error("invalid key binding JWT component")]
    InvalidKeyBindingJwt,

    /// A disclosure is not valid base64url-encoded JSON.
    #[error("invalid disclosure encoding")]
    InvalidDisclosureEncoding,

    /// The input contains more disclosures than the configured limit.
    #[error("too many SD-JWT disclosures")]
    TooManyDisclosures,

    /// A disclosure exceeds the accepted byte limit.
    #[error("SD-JWT disclosure exceeds accepted bounds")]
    DisclosureTooLarge,

    /// The complete SD-JWT exceeds the accepted byte limit.
    #[error("SD-JWT input exceeds accepted bounds")]
    InputTooLarge,

    /// The JWS JSON input contains more signatures than the configured limit.
    #[error("too many SD-JWT JSON signatures")]
    TooManySignatures,

    /// A decoded disclosure has an invalid array shape.
    #[error("invalid disclosure format")]
    InvalidDisclosureFormat,

    /// A disclosed object-property name is empty, reserved, or otherwise invalid.
    #[error("invalid disclosure claim name")]
    InvalidDisclosureClaimName,

    /// Issuance input violates the selected policy or structural limits.
    #[error("invalid SD-JWT issuance input")]
    InvalidIssuanceInput,

    /// The declared disclosure hash algorithm is unsupported.
    #[error("unsupported SD-JWT hash algorithm")]
    UnsupportedHashAlgorithm,

    /// The `_sd_alg` claim is not a supported string value.
    #[error("invalid SD-JWT hash algorithm claim")]
    InvalidHashAlgorithmClaim,

    /// The issuer payload is not a JSON object.
    #[error("SD-JWT payload must be a JSON object")]
    PayloadNotObject,

    /// A reserved SD-JWT claim appears outside its permitted structural position.
    #[error("invalid SD-JWT reserved claim placement")]
    InvalidReservedClaimPlacement,

    /// An array disclosure placeholder has an invalid shape or digest.
    #[error("invalid SD-JWT digest placeholder")]
    InvalidDigestPlaceholder,

    /// The issuer payload contains the same disclosure digest more than once.
    #[error("duplicate SD-JWT digest")]
    DuplicateDigest,

    /// The presentation supplies the same disclosure more than once.
    #[error("duplicate SD-JWT disclosure")]
    DuplicateDisclosure,

    /// A supplied disclosure is not bound by the issuer payload.
    #[error("unmatched SD-JWT disclosure")]
    UnmatchedDisclosure,

    /// A requested presentation path is absent from the reconstructed claims.
    #[error("requested SD-JWT claim path was not found")]
    RequestedPathNotFound,

    /// Applying a disclosure would replace an existing claim.
    #[error("conflicting SD-JWT disclosure claim")]
    ConflictingDisclosureClaim,

    /// Disclosure processing exceeded the configured nesting depth.
    #[error("SD-JWT processing depth exceeded")]
    ProcessingDepthExceeded,

    /// Disclosure processing exceeded the configured node budget.
    #[error("SD-JWT processing node limit exceeded")]
    ProcessingNodeLimitExceeded,

    /// JSON serialization or deserialization failed.
    #[error("serialization error")]
    Serialization,

    /// A base64url component is malformed.
    #[error("base64url decoding error")]
    Base64Url,

    /// A cryptographic primitive rejected the operation.
    #[error("cryptographic error")]
    Crypto,

    /// JWT encoding, decoding, or signature processing failed.
    #[error("JWT error")]
    Jwt,

    /// Receipt verification policy is incomplete or internally inconsistent.
    #[error("invalid SD-JWT receipt policy")]
    InvalidReceiptPolicy,

    /// An authenticated receipt claim does not match the expected issuer context.
    #[error("SD-JWT receipt issuer claim mismatch")]
    ReceiptClaimMismatch,

    /// A receipt temporal claim is malformed or forms an invalid interval.
    #[error("invalid SD-JWT receipt temporal claim")]
    InvalidReceiptTemporalClaim,

    /// The receipt is expired or not yet valid at the verification time.
    #[error("SD-JWT receipt is not currently valid")]
    ReceiptExpired,

    /// Receipt policy requires holder binding, but no binding is present.
    #[error("missing SD-JWT receipt holder binding")]
    MissingReceiptHolderBinding,

    /// The receipt holder-binding proof is malformed or fails validation.
    #[error("invalid SD-JWT receipt holder binding")]
    InvalidReceiptHolderBinding,

    /// The authenticated holder key does not match the expected holder.
    #[error("SD-JWT receipt holder binding mismatch")]
    ReceiptHolderBindingMismatch,

    /// A key-binding JWT is present where receipt policy forbids one.
    #[error("unexpected SD-JWT receipt key binding JWT")]
    UnexpectedReceiptKeyBindingJwt,

    /// Verification policy is incomplete or exceeds supported bounds.
    #[error("invalid SD-JWT verification policy")]
    InvalidVerificationPolicy,

    /// A credential temporal claim is malformed or forms an invalid interval.
    #[error("invalid SD-JWT temporal claim")]
    InvalidTemporalClaim,

    /// The credential expired at or before the verification time.
    #[error("SD-JWT credential has expired")]
    CredentialExpired,

    /// The credential is not valid at the verification time.
    #[error("SD-JWT credential is not yet valid")]
    CredentialNotYetValid,

    /// Issuance attempted to hide a claim that RFC 9901 requires to remain visible.
    #[error("SD-JWT claim must not be selectively disclosable")]
    NonSelectivelyDisclosableClaim,

    /// A configured disclosure path did not identify any claim.
    #[error("SD-JWT disclosure path did not match a claim")]
    DisclosurePathNotFound,

    /// Required credential-status evidence is absent, invalid, or non-valid.
    #[error("SD-JWT credential status was not verified")]
    CredentialStatusNotVerified,
}

impl From<Base64UrlError> for SdJwtEnvelopeError {
    fn from(_: Base64UrlError) -> Self {
        SdJwtEnvelopeError::Base64Url
    }
}

impl From<AlgorithmError> for SdJwtEnvelopeError {
    fn from(_: AlgorithmError) -> Self {
        SdJwtEnvelopeError::Crypto
    }
}

impl From<CryptoError> for SdJwtEnvelopeError {
    fn from(_: CryptoError) -> Self {
        SdJwtEnvelopeError::Crypto
    }
}

impl From<serde_json::Error> for SdJwtEnvelopeError {
    fn from(_: serde_json::Error) -> Self {
        SdJwtEnvelopeError::Serialization
    }
}

impl From<reallyme_jose::jwt::JwtError> for SdJwtEnvelopeError {
    fn from(_: reallyme_jose::jwt::JwtError) -> Self {
        SdJwtEnvelopeError::Jwt
    }
}

impl From<SdJwtEnvelopeError> for IdentityCoreErrorReason {
    fn from(error: SdJwtEnvelopeError) -> Self {
        match error {
            SdJwtEnvelopeError::InvalidCompactSerialization => {
                Self::IDENTITY_CORE_ERROR_REASON_SD_JWT_MALFORMED_COMPACT
            }
            SdJwtEnvelopeError::InvalidJsonSerialization => {
                Self::IDENTITY_CORE_ERROR_REASON_SD_JWT_INVALID_JSON_SERIALIZATION
            }
            SdJwtEnvelopeError::InvalidIssuerJwt => {
                Self::IDENTITY_CORE_ERROR_REASON_SD_JWT_INVALID_ISSUER_JWT
            }
            SdJwtEnvelopeError::InvalidKeyBindingJwt => {
                Self::IDENTITY_CORE_ERROR_REASON_SD_JWT_INVALID_KEY_BINDING_JWT
            }
            SdJwtEnvelopeError::InvalidDisclosureEncoding => {
                Self::IDENTITY_CORE_ERROR_REASON_SD_JWT_INVALID_DISCLOSURE_ENCODING
            }
            SdJwtEnvelopeError::TooManyDisclosures => {
                Self::IDENTITY_CORE_ERROR_REASON_SD_JWT_TOO_MANY_DISCLOSURES
            }
            SdJwtEnvelopeError::DisclosureTooLarge => {
                Self::IDENTITY_CORE_ERROR_REASON_SD_JWT_DISCLOSURE_TOO_LARGE
            }
            SdJwtEnvelopeError::InputTooLarge => {
                Self::IDENTITY_CORE_ERROR_REASON_SD_JWT_MALFORMED_COMPACT
            }
            SdJwtEnvelopeError::TooManySignatures => {
                Self::IDENTITY_CORE_ERROR_REASON_SD_JWT_INVALID_JSON_SERIALIZATION
            }
            SdJwtEnvelopeError::InvalidDisclosureFormat => {
                Self::IDENTITY_CORE_ERROR_REASON_SD_JWT_INVALID_DISCLOSURE_FORMAT
            }
            SdJwtEnvelopeError::InvalidDisclosureClaimName => {
                Self::IDENTITY_CORE_ERROR_REASON_SD_JWT_INVALID_DISCLOSURE_CLAIM_NAME
            }
            SdJwtEnvelopeError::InvalidIssuanceInput => {
                Self::IDENTITY_CORE_ERROR_REASON_SD_JWT_INVALID_ISSUANCE_INPUT
            }
            SdJwtEnvelopeError::UnsupportedHashAlgorithm => {
                Self::IDENTITY_CORE_ERROR_REASON_SD_JWT_UNSUPPORTED_HASH_ALGORITHM
            }
            SdJwtEnvelopeError::InvalidHashAlgorithmClaim => {
                Self::IDENTITY_CORE_ERROR_REASON_SD_JWT_INVALID_HASH_ALGORITHM_CLAIM
            }
            SdJwtEnvelopeError::PayloadNotObject => {
                Self::IDENTITY_CORE_ERROR_REASON_SD_JWT_PAYLOAD_NOT_OBJECT
            }
            SdJwtEnvelopeError::InvalidReservedClaimPlacement => {
                Self::IDENTITY_CORE_ERROR_REASON_SD_JWT_INVALID_RESERVED_CLAIM_PLACEMENT
            }
            SdJwtEnvelopeError::InvalidDigestPlaceholder => {
                Self::IDENTITY_CORE_ERROR_REASON_SD_JWT_INVALID_DIGEST_PLACEHOLDER
            }
            SdJwtEnvelopeError::DuplicateDigest => {
                Self::IDENTITY_CORE_ERROR_REASON_SD_JWT_DUPLICATE_DIGEST
            }
            SdJwtEnvelopeError::DuplicateDisclosure => {
                Self::IDENTITY_CORE_ERROR_REASON_SD_JWT_DUPLICATE_DISCLOSURE
            }
            SdJwtEnvelopeError::UnmatchedDisclosure => {
                Self::IDENTITY_CORE_ERROR_REASON_SD_JWT_UNMATCHED_DISCLOSURE
            }
            SdJwtEnvelopeError::RequestedPathNotFound => {
                Self::IDENTITY_CORE_ERROR_REASON_SD_JWT_UNMATCHED_DISCLOSURE
            }
            SdJwtEnvelopeError::ConflictingDisclosureClaim => {
                Self::IDENTITY_CORE_ERROR_REASON_SD_JWT_CONFLICTING_DISCLOSURE_CLAIM
            }
            SdJwtEnvelopeError::ProcessingDepthExceeded => {
                Self::IDENTITY_CORE_ERROR_REASON_SD_JWT_PROCESSING_DEPTH_EXCEEDED
            }
            SdJwtEnvelopeError::ProcessingNodeLimitExceeded => {
                Self::IDENTITY_CORE_ERROR_REASON_SD_JWT_PROCESSING_NODE_LIMIT_EXCEEDED
            }
            SdJwtEnvelopeError::Serialization => {
                Self::IDENTITY_CORE_ERROR_REASON_SD_JWT_SERIALIZATION
            }
            SdJwtEnvelopeError::Base64Url => Self::IDENTITY_CORE_ERROR_REASON_SD_JWT_BASE64URL,
            SdJwtEnvelopeError::Crypto => Self::IDENTITY_CORE_ERROR_REASON_SD_JWT_CRYPTO,
            SdJwtEnvelopeError::Jwt => Self::IDENTITY_CORE_ERROR_REASON_SD_JWT_JWT,
            SdJwtEnvelopeError::InvalidReceiptPolicy => {
                Self::IDENTITY_CORE_ERROR_REASON_INVALID_INPUT
            }
            SdJwtEnvelopeError::ReceiptClaimMismatch
            | SdJwtEnvelopeError::InvalidReceiptTemporalClaim
            | SdJwtEnvelopeError::ReceiptExpired => {
                Self::IDENTITY_CORE_ERROR_REASON_SD_JWT_INVALID_ISSUER_JWT
            }
            SdJwtEnvelopeError::MissingReceiptHolderBinding
            | SdJwtEnvelopeError::InvalidReceiptHolderBinding
            | SdJwtEnvelopeError::ReceiptHolderBindingMismatch
            | SdJwtEnvelopeError::UnexpectedReceiptKeyBindingJwt => {
                Self::IDENTITY_CORE_ERROR_REASON_SD_JWT_HOLDER_BINDING_FAILED
            }
            SdJwtEnvelopeError::InvalidVerificationPolicy => {
                Self::IDENTITY_CORE_ERROR_REASON_INVALID_INPUT
            }
            SdJwtEnvelopeError::InvalidTemporalClaim
            | SdJwtEnvelopeError::CredentialExpired
            | SdJwtEnvelopeError::CredentialNotYetValid => {
                Self::IDENTITY_CORE_ERROR_REASON_CREDENTIAL_INVALID_VALIDITY_WINDOW
            }
            SdJwtEnvelopeError::NonSelectivelyDisclosableClaim => {
                Self::IDENTITY_CORE_ERROR_REASON_SD_JWT_INVALID_DISCLOSURE_CLAIM_NAME
            }
            SdJwtEnvelopeError::DisclosurePathNotFound => {
                Self::IDENTITY_CORE_ERROR_REASON_SD_JWT_INVALID_DISCLOSURE_CLAIM_NAME
            }
            SdJwtEnvelopeError::CredentialStatusNotVerified => {
                Self::IDENTITY_CORE_ERROR_REASON_CREDENTIAL_STATUS_CHECK_FAILED
            }
        }
    }
}

#[cfg(test)]
#[path = "error_proto_error_tests.rs"]
mod proto_error_tests;
