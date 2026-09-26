// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_codec::base64url::Base64UrlError;
use reallyme_crypto::core::CryptoError;
use reallyme_crypto::dispatch::AlgorithmError;
use reallyme_ssi_proto::generated::proto::reallyme::identity_core::v1::IdentityCoreErrorReason;
use thiserror::Error;

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum SdJwtEnvelopeError {
    #[error("invalid SD-JWT compact serialization")]
    InvalidCompactSerialization,

    #[error("invalid SD-JWT JWS JSON serialization")]
    InvalidJsonSerialization,

    #[error("invalid issuer-signed JWT component")]
    InvalidIssuerJwt,

    #[error("invalid key binding JWT component")]
    InvalidKeyBindingJwt,

    #[error("invalid disclosure encoding")]
    InvalidDisclosureEncoding,

    #[error("too many SD-JWT disclosures")]
    TooManyDisclosures,

    #[error("SD-JWT disclosure exceeds accepted bounds")]
    DisclosureTooLarge,

    #[error("SD-JWT input exceeds accepted bounds")]
    InputTooLarge,

    #[error("too many SD-JWT JSON signatures")]
    TooManySignatures,

    #[error("invalid disclosure format")]
    InvalidDisclosureFormat,

    #[error("invalid disclosure claim name")]
    InvalidDisclosureClaimName,

    #[error("invalid SD-JWT issuance input")]
    InvalidIssuanceInput,

    #[error("unsupported SD-JWT hash algorithm")]
    UnsupportedHashAlgorithm,

    #[error("invalid SD-JWT hash algorithm claim")]
    InvalidHashAlgorithmClaim,

    #[error("SD-JWT payload must be a JSON object")]
    PayloadNotObject,

    #[error("invalid SD-JWT reserved claim placement")]
    InvalidReservedClaimPlacement,

    #[error("invalid SD-JWT digest placeholder")]
    InvalidDigestPlaceholder,

    #[error("duplicate SD-JWT digest")]
    DuplicateDigest,

    #[error("duplicate SD-JWT disclosure")]
    DuplicateDisclosure,

    #[error("unmatched SD-JWT disclosure")]
    UnmatchedDisclosure,

    #[error("conflicting SD-JWT disclosure claim")]
    ConflictingDisclosureClaim,

    #[error("SD-JWT processing depth exceeded")]
    ProcessingDepthExceeded,

    #[error("SD-JWT processing node limit exceeded")]
    ProcessingNodeLimitExceeded,

    #[error("serialization error")]
    Serialization,

    #[error("base64url decoding error")]
    Base64Url,

    #[error("cryptographic error")]
    Crypto,

    #[error("JWT error")]
    Jwt,

    #[error("invalid SD-JWT receipt policy")]
    InvalidReceiptPolicy,

    #[error("SD-JWT receipt issuer claim mismatch")]
    ReceiptClaimMismatch,

    #[error("invalid SD-JWT receipt temporal claim")]
    InvalidReceiptTemporalClaim,

    #[error("SD-JWT receipt is not currently valid")]
    ReceiptExpired,

    #[error("missing SD-JWT receipt holder binding")]
    MissingReceiptHolderBinding,

    #[error("invalid SD-JWT receipt holder binding")]
    InvalidReceiptHolderBinding,

    #[error("SD-JWT receipt holder binding mismatch")]
    ReceiptHolderBindingMismatch,

    #[error("unexpected SD-JWT receipt key binding JWT")]
    UnexpectedReceiptKeyBindingJwt,

    #[error("invalid SD-JWT verification policy")]
    InvalidVerificationPolicy,

    #[error("invalid SD-JWT temporal claim")]
    InvalidTemporalClaim,

    #[error("SD-JWT credential has expired")]
    CredentialExpired,

    #[error("SD-JWT credential is not yet valid")]
    CredentialNotYetValid,

    #[error("SD-JWT claim must not be selectively disclosable")]
    NonSelectivelyDisclosableClaim,

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
            SdJwtEnvelopeError::CredentialStatusNotVerified => {
                Self::IDENTITY_CORE_ERROR_REASON_CREDENTIAL_STATUS_CHECK_FAILED
            }
        }
    }
}

#[cfg(test)]
#[path = "error_proto_error_tests.rs"]
mod proto_error_tests;
