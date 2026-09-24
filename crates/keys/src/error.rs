// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_ssi_proto::generated::proto::reallyme::identity_core::v1::IdentityCoreErrorReason;
use thiserror::Error;

/// Typed failures for key-set operations.
///
/// These variants intentionally carry no dynamic strings or raw bytes. Key
/// identifiers, public keys, private key bytes, and encoded private keys may be
/// sensitive in logs, crash reports, or FFI mappings, so callers get stable
/// machine-readable reasons without accidental data disclosure.
#[derive(Debug, Clone, Copy, Eq, Error, PartialEq)]
pub enum KeySetError {
    /// Verification method identifier was empty, oversized, or log-unsafe.
    #[error("invalid verification method id")]
    InvalidVerificationMethodId,

    /// Private key bytes were empty or exceeded the configured key-size bound.
    #[error("invalid private key material")]
    InvalidPrivateKeyMaterial,

    /// Exported private key material was not valid base64.
    #[error("invalid private key encoding")]
    InvalidPrivateKeyEncoding,

    /// Public key was not a valid multibase-encoded multikey.
    #[error("invalid public key multibase")]
    InvalidPublicKeyMultibase,

    /// Requested private key is not present in the key set.
    #[error("missing private key")]
    MissingPrivateKey,

    /// Requested public key is not present in the key set.
    #[error("missing public key")]
    MissingPublicKey,
}

impl From<KeySetError> for IdentityCoreErrorReason {
    fn from(error: KeySetError) -> Self {
        match error {
            KeySetError::InvalidVerificationMethodId
            | KeySetError::InvalidPublicKeyMultibase
            | KeySetError::MissingPublicKey => {
                Self::IDENTITY_CORE_ERROR_REASON_DID_INVALID_VERIFICATION_METHOD
            }
            KeySetError::InvalidPrivateKeyMaterial
            | KeySetError::InvalidPrivateKeyEncoding
            | KeySetError::MissingPrivateKey => Self::IDENTITY_CORE_ERROR_REASON_INVALID_SIGNATURE,
        }
    }
}
