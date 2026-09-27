// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_ssi_proto::generated::proto::reallyme::identity_core::v1::IdentityCoreErrorReason;
use thiserror::Error;

/// Typed failures for SD-JWT presentation handling.
#[derive(Debug, Error)]
pub enum SdJwtVpError {
    /// SubjectPrivateBundle is malformed or inconsistent
    #[error("invalid subject private bundle")]
    InvalidBundle,

    /// Requested claim path does not exist in the bundle
    #[error("requested claim not found")]
    ClaimNotFound,

    /// Disclosure is malformed, unverifiable, or fails Merkle verification
    #[error("invalid disclosure")]
    InvalidDisclosure,

    /// Serialization / deserialization failure
    #[error("serialization error")]
    Serialization,

    /// Cryptographic failure (signature verification, key mismatch, etc.)
    #[error("crypto error")]
    Crypto,

    /// A compact token exceeded a pre-verification resource ceiling.
    #[error("resource limit exceeded")]
    ResourceLimit,

    /// A holder-bound credential was presented without a verifiable KB-JWT.
    #[error("missing key binding proof")]
    MissingKeyBinding,

    /// The credential envelope is not the one committed by the issuer SD-JWT.
    #[error("credential envelope binding mismatch")]
    EnvelopeBindingMismatch,

    /// The authenticated key-binding proof covers a different disclosure set.
    #[error("presentation disclosure set binding mismatch")]
    DisclosureSetMismatch,
}

impl From<SdJwtVpError> for IdentityCoreErrorReason {
    fn from(error: SdJwtVpError) -> Self {
        match error {
            SdJwtVpError::InvalidBundle => {
                Self::IDENTITY_CORE_ERROR_REASON_CREDENTIAL_INVALID_ENVELOPE
            }
            SdJwtVpError::ClaimNotFound => Self::IDENTITY_CORE_ERROR_REASON_CLAIMS_UNKNOWN_CLAIM,
            SdJwtVpError::InvalidDisclosure => {
                Self::IDENTITY_CORE_ERROR_REASON_SD_JWT_INVALID_DISCLOSURE
            }
            SdJwtVpError::Serialization => Self::IDENTITY_CORE_ERROR_REASON_SERIALIZATION_FAILED,
            SdJwtVpError::Crypto => Self::IDENTITY_CORE_ERROR_REASON_INVALID_SIGNATURE,
            SdJwtVpError::ResourceLimit => Self::IDENTITY_CORE_ERROR_REASON_RESOURCE_LIMIT_EXCEEDED,
            SdJwtVpError::MissingKeyBinding => {
                Self::IDENTITY_CORE_ERROR_REASON_SD_JWT_HOLDER_BINDING_FAILED
            }
            SdJwtVpError::EnvelopeBindingMismatch => {
                Self::IDENTITY_CORE_ERROR_REASON_CREDENTIAL_INVALID_ENVELOPE
            }
            SdJwtVpError::DisclosureSetMismatch => {
                Self::IDENTITY_CORE_ERROR_REASON_SD_JWT_HOLDER_BINDING_FAILED
            }
        }
    }
}
