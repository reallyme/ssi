// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_codec::base64url::{base64url_to_bytes, bytes_to_base64url};
use reallyme_ssi_proto::generated::proto::reallyme::identity_core::v1::IdentityCoreErrorReason;
use serde_json::Value;
use thiserror::Error;

const DID_JWK_PREFIX: &str = "did:jwk:";
const DID_JWK_FRAGMENT: &str = "#0";
const PRIVATE_JWK_MEMBERS: &[&str] = &["d", "p", "q", "dp", "dq", "qi", "oth", "k"];

/// Audit-safe did:jwk failure reasons.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DidJwkErrorReason {
    /// The DID did not start with `did:jwk:`.
    InvalidPrefix,
    /// The method-specific identifier was empty.
    EmptyIdentifier,
    /// The method-specific identifier was not unpadded base64url.
    InvalidBase64Url,
    /// The decoded bytes were not a JSON object.
    InvalidJson,
    /// The JWK omitted required public key members for its key type.
    InvalidPublicJwk,
    /// A private or symmetric JWK member was present.
    PrivateKeyMaterial,
    /// JSON serialization failed.
    SerializationFailed,
}

/// Typed did:jwk method error.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[error("invalid did:jwk method identifier")]
pub struct DidJwkError {
    /// Audit-safe reason for the failure.
    pub reason: DidJwkErrorReason,
}

impl DidJwkError {
    const fn new(reason: DidJwkErrorReason) -> Self {
        Self { reason }
    }
}

impl From<DidJwkErrorReason> for IdentityCoreErrorReason {
    fn from(reason: DidJwkErrorReason) -> Self {
        match reason {
            DidJwkErrorReason::InvalidPrefix => Self::IDENTITY_CORE_ERROR_REASON_DID_INVALID_PREFIX,
            DidJwkErrorReason::EmptyIdentifier => {
                Self::IDENTITY_CORE_ERROR_REASON_DID_EMPTY_IDENTIFIER
            }
            DidJwkErrorReason::InvalidBase64Url => {
                Self::IDENTITY_CORE_ERROR_REASON_DID_INVALID_BASE64URL
            }
            DidJwkErrorReason::InvalidJson => Self::IDENTITY_CORE_ERROR_REASON_INVALID_ENCODING,
            DidJwkErrorReason::InvalidPublicJwk => {
                Self::IDENTITY_CORE_ERROR_REASON_DID_INVALID_PUBLIC_JWK
            }
            DidJwkErrorReason::PrivateKeyMaterial => {
                Self::IDENTITY_CORE_ERROR_REASON_DID_PRIVATE_KEY_MATERIAL
            }
            DidJwkErrorReason::SerializationFailed => {
                Self::IDENTITY_CORE_ERROR_REASON_DID_JSON_SERIALIZATION_FAILED
            }
        }
    }
}

impl From<DidJwkError> for IdentityCoreErrorReason {
    fn from(error: DidJwkError) -> Self {
        error.reason.into()
    }
}

#[cfg(test)]
#[path = "lib_proto_error_tests.rs"]
mod proto_error_tests;

/// Decoded did:jwk identifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DidJwkIdentifier {
    /// Public JWK carried by the identifier.
    pub jwk: Value,
}

/// Generate a did:jwk identifier from a public JWK value.
pub fn generate_did_jwk(jwk: &Value) -> Result<String, DidJwkError> {
    validate_public_jwk(jwk)?;
    let json = serde_json::to_vec(jwk)
        .map_err(|_| DidJwkError::new(DidJwkErrorReason::SerializationFailed))?;
    generate_did_jwk_from_json_bytes(&json)
}

/// Generate a did:jwk identifier from an exact public JWK JSON serialization.
///
/// did:jwk identifiers commit to the bytes of the JSON serialization. This
/// entry point exists so callers with published vectors or canonicalized JSON
/// can preserve that representation instead of depending on map serialization
/// order from a generic JSON value.
pub fn generate_did_jwk_from_json_bytes(json: &[u8]) -> Result<String, DidJwkError> {
    let jwk: Value = serde_json::from_slice(json)
        .map_err(|_| DidJwkError::new(DidJwkErrorReason::InvalidJson))?;
    validate_public_jwk(&jwk)?;
    Ok(format!("{DID_JWK_PREFIX}{}", bytes_to_base64url(json)))
}

/// Return the only valid verification-method DID URL for a did:jwk identifier.
pub fn did_jwk_url(did: &str) -> Result<String, DidJwkError> {
    parse_did_jwk(did)?;
    Ok(format!("{did}{DID_JWK_FRAGMENT}"))
}

/// Validate and decode a did:jwk identifier.
pub fn parse_did_jwk(did: &str) -> Result<DidJwkIdentifier, DidJwkError> {
    let encoded = did
        .strip_prefix(DID_JWK_PREFIX)
        .ok_or(DidJwkError::new(DidJwkErrorReason::InvalidPrefix))?;
    if encoded.is_empty() {
        return Err(DidJwkError::new(DidJwkErrorReason::EmptyIdentifier));
    }
    if !encoded.bytes().all(is_base64url_byte) {
        return Err(DidJwkError::new(DidJwkErrorReason::InvalidBase64Url));
    }

    let decoded = base64url_to_bytes(encoded)
        .map_err(|_| DidJwkError::new(DidJwkErrorReason::InvalidBase64Url))?;
    let jwk: Value = serde_json::from_slice(&decoded)
        .map_err(|_| DidJwkError::new(DidJwkErrorReason::InvalidJson))?;
    validate_public_jwk(&jwk)?;

    Ok(DidJwkIdentifier { jwk })
}

/// Return true when the DID is a syntactically valid did:jwk identifier.
pub fn is_valid_did_jwk(did: &str) -> bool {
    parse_did_jwk(did).is_ok()
}

fn validate_public_jwk(jwk: &Value) -> Result<(), DidJwkError> {
    let object = jwk
        .as_object()
        .ok_or(DidJwkError::new(DidJwkErrorReason::InvalidPublicJwk))?;

    for member in PRIVATE_JWK_MEMBERS {
        if object.contains_key(*member) {
            return Err(DidJwkError::new(DidJwkErrorReason::PrivateKeyMaterial));
        }
    }

    match object.get("kty").and_then(Value::as_str) {
        Some("OKP") => require_string_members(object, &["crv", "x"]),
        Some("EC") => require_string_members(object, &["crv", "x", "y"]),
        Some("RSA") => require_string_members(object, &["n", "e"]),
        _ => Err(DidJwkError::new(DidJwkErrorReason::InvalidPublicJwk)),
    }
}

fn require_string_members(
    object: &serde_json::Map<String, Value>,
    members: &[&str],
) -> Result<(), DidJwkError> {
    for member in members {
        match object.get(*member).and_then(Value::as_str) {
            Some(value) if !value.is_empty() => {}
            _ => return Err(DidJwkError::new(DidJwkErrorReason::InvalidPublicJwk)),
        }
    }
    Ok(())
}

fn is_base64url_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_'
}

#[cfg(test)]
#[path = "lib_tests.rs"]
mod tests;
