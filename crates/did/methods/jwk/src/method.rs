// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_codec::base64url::{base64url_to_bytes, bytes_to_base64url};
use reallyme_ssi_proto::generated::proto::reallyme::identity_core::v1::IdentityCoreErrorReason;
use serde_json::Value;
use thiserror::Error;

const MAX_ENCODED_JWK_BYTES: usize = 1_398_104;
const DID_JWK_PREFIX: &str = "did:jwk:";
const DID_JWK_FRAGMENT: &str = "#0";
const ML_DSA_44_PUBLIC_KEY_LEN: usize = 1_312;
const ML_DSA_65_PUBLIC_KEY_LEN: usize = 1_952;
const ML_DSA_87_PUBLIC_KEY_LEN: usize = 2_592;
const MIN_RSA_MODULUS_BITS: usize = 2_048;
const MAX_RSA_MODULUS_BITS: usize = 16_384;
const MAX_RSA_EXPONENT_BYTES: usize = 8;
const BITS_PER_BYTE: usize = 8;
const PRIVATE_JWK_MEMBERS: &[&str] = &[
    "d",
    "p",
    "q",
    "dp",
    "dq",
    "qi",
    "oth",
    "k",
    "priv",
    "privateKey",
    "secretKey",
];

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
    identity_core_primitives::validate_json::validate_json(json)
        .map_err(|_| DidJwkError::new(DidJwkErrorReason::InvalidJson))?;
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

    // Bound allocation before decoding an untrusted method-specific identifier.
    if encoded.len() > MAX_ENCODED_JWK_BYTES {
        return Err(DidJwkError::new(DidJwkErrorReason::InvalidJson));
    }
    let decoded = base64url_to_bytes(encoded)
        .map_err(|_| DidJwkError::new(DidJwkErrorReason::InvalidBase64Url))?;
    identity_core_primitives::validate_json::validate_json(&decoded)
        .map_err(|_| DidJwkError::new(DidJwkErrorReason::InvalidJson))?;
    let jwk: Value = serde_json::from_slice(&decoded)
        .map_err(|_| DidJwkError::new(DidJwkErrorReason::InvalidJson))?;
    validate_public_jwk(&jwk)?;

    Ok(DidJwkIdentifier { jwk })
}

/// Return true when the DID is a syntactically valid did:jwk identifier.
pub fn is_valid_did_jwk(did: &str) -> bool {
    parse_did_jwk(did).is_ok()
}

/// Validate that a JSON value is an asymmetric public JWK accepted by this
/// method implementation.
///
/// This is also used by DID-document validators so embedded `publicKeyJwk`
/// values receive the same private-material, required-member, and metadata
/// checks as a `did:jwk` method-specific identifier.
pub fn validate_public_jwk(jwk: &Value) -> Result<(), DidJwkError> {
    let object = jwk
        .as_object()
        .ok_or(DidJwkError::new(DidJwkErrorReason::InvalidPublicJwk))?;

    for member in PRIVATE_JWK_MEMBERS {
        if object.contains_key(*member) {
            return Err(DidJwkError::new(DidJwkErrorReason::PrivateKeyMaterial));
        }
    }

    validate_optional_metadata(object)?;
    let key_type = object
        .get("kty")
        .and_then(Value::as_str)
        .ok_or(DidJwkError::new(DidJwkErrorReason::InvalidPublicJwk))?;
    match key_type {
        "OKP" => {
            require_string_members(object, &["crv", "x"])?;
            validate_okp_public_key(object)?;
        }
        "EC" => {
            require_string_members(object, &["crv", "x", "y"])?;
            validate_ec_public_key(object)?;
        }
        "RSA" => {
            require_string_members(object, &["n", "e"])?;
            validate_rsa_public_key(object)?;
        }
        "AKP" => {
            require_string_members(object, &["alg", "pub"])?;
            validate_akp_public_key(object)?;
        }
        _ => return Err(DidJwkError::new(DidJwkErrorReason::InvalidPublicJwk)),
    }
    validate_algorithm_metadata(object, key_type)
}

fn validate_algorithm_metadata(
    object: &serde_json::Map<String, Value>,
    key_type: &str,
) -> Result<(), DidJwkError> {
    let algorithm = object.get("alg").and_then(Value::as_str);
    if algorithm.is_some_and(|value| value == "none" || value.starts_with("HS")) {
        return Err(DidJwkError::new(DidJwkErrorReason::InvalidPublicJwk));
    }
    let curve = object.get("crv").and_then(Value::as_str);
    let algorithm_matches = match (key_type, curve, algorithm) {
        (_, _, None) => true,
        ("OKP", Some("Ed25519" | "Ed448"), Some("EdDSA")) => true,
        ("OKP", Some("X25519" | "X448"), Some(value)) => value.starts_with("ECDH-ES"),
        ("EC", Some("P-256"), Some("ES256"))
        | ("EC", Some("P-384"), Some("ES384"))
        | ("EC", Some("P-521"), Some("ES512"))
        | ("EC", Some("secp256k1"), Some("ES256K")) => true,
        ("EC", _, Some(value)) if value.starts_with("ECDH-ES") => true,
        ("RSA", _, Some(value)) => {
            value.starts_with("RS") || value.starts_with("PS") || value.starts_with("RSA-OAEP")
        }
        ("AKP", _, Some(value)) => !value.is_empty(),
        _ => false,
    };
    if !algorithm_matches {
        return Err(DidJwkError::new(DidJwkErrorReason::InvalidPublicJwk));
    }
    match object.get("use").and_then(Value::as_str) {
        Some("sig")
            if matches!(curve, Some("X25519" | "X448"))
                || algorithm.is_some_and(|value| {
                    value.starts_with("ECDH-ES") || value.starts_with("RSA-OAEP")
                }) =>
        {
            Err(DidJwkError::new(DidJwkErrorReason::InvalidPublicJwk))
        }
        Some("enc")
            if matches!(curve, Some("Ed25519" | "Ed448"))
                || algorithm.is_some_and(|value| {
                    value.starts_with("ES") || value.starts_with("RS") || value.starts_with("PS")
                }) =>
        {
            Err(DidJwkError::new(DidJwkErrorReason::InvalidPublicJwk))
        }
        _ => Ok(()),
    }
}

fn validate_optional_metadata(object: &serde_json::Map<String, Value>) -> Result<(), DidJwkError> {
    let use_value = match object.get("use") {
        Some(Value::String(value)) if !value.is_empty() => Some(value.as_str()),
        Some(_) => return Err(DidJwkError::new(DidJwkErrorReason::InvalidPublicJwk)),
        None => None,
    };
    for name in ["alg", "kid"] {
        if object
            .get(name)
            .is_some_and(|value| value.as_str().is_none_or(str::is_empty))
        {
            return Err(DidJwkError::new(DidJwkErrorReason::InvalidPublicJwk));
        }
    }
    let Some(key_operations) = object.get("key_ops") else {
        return Ok(());
    };
    let operations = key_operations
        .as_array()
        .filter(|operations| !operations.is_empty())
        .ok_or(DidJwkError::new(DidJwkErrorReason::InvalidPublicJwk))?;
    let mut seen = std::collections::BTreeSet::new();
    for operation in operations {
        let operation = operation
            .as_str()
            .filter(|operation| !operation.is_empty())
            .ok_or(DidJwkError::new(DidJwkErrorReason::InvalidPublicJwk))?;
        if !seen.insert(operation) {
            return Err(DidJwkError::new(DidJwkErrorReason::InvalidPublicJwk));
        }
        // RFC 7517 permits extension values for both `use` and `key_ops`.
        // Apply the registered sig/enc consistency rules when those standard
        // values are used, and preserve forward-compatible extension names.
        if matches!(use_value, Some("sig"))
            && matches!(
                operation,
                "encrypt" | "decrypt" | "wrapKey" | "unwrapKey" | "deriveKey" | "deriveBits"
            )
            || matches!(use_value, Some("enc")) && matches!(operation, "sign" | "verify")
        {
            return Err(DidJwkError::new(DidJwkErrorReason::InvalidPublicJwk));
        }
    }
    Ok(())
}

fn decode_base64url_member(
    object: &serde_json::Map<String, Value>,
    member: &str,
) -> Result<Vec<u8>, DidJwkError> {
    let encoded = object
        .get(member)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or(DidJwkError::new(DidJwkErrorReason::InvalidPublicJwk))?;
    let decoded = base64url_to_bytes(encoded)
        .map_err(|_| DidJwkError::new(DidJwkErrorReason::InvalidPublicJwk))?;
    if decoded.is_empty() || bytes_to_base64url(&decoded) != encoded {
        return Err(DidJwkError::new(DidJwkErrorReason::InvalidPublicJwk));
    }
    Ok(decoded)
}

fn validate_okp_public_key(object: &serde_json::Map<String, Value>) -> Result<(), DidJwkError> {
    use reallyme_crypto::operations::key_encoding::{
        encode_ed25519_public_key, encode_x25519_public_key,
    };

    let public_key = decode_base64url_member(object, "x")?;
    let valid = match object.get("crv").and_then(Value::as_str) {
        Some("Ed25519") => {
            encode_ed25519_public_key(&public_key).is_ok() && validate_ed25519_point(&public_key)
        }
        Some("X25519") => encode_x25519_public_key(&public_key).is_ok(),
        // Ed448 and X448 are registered OKP curves. The shared crypto backend
        // does not operate on them, so this boundary enforces their normative
        // fixed-width encodings without claiming algorithm support.
        Some("Ed448") => public_key.len() == 57,
        Some("X448") => public_key.len() == 56,
        _ => false,
    };
    valid
        .then_some(())
        .ok_or(DidJwkError::new(DidJwkErrorReason::InvalidPublicJwk))
}

fn validate_ed25519_point(public_key: &[u8]) -> bool {
    let Ok(encoded) = <[u8; 32]>::try_from(public_key) else {
        return false;
    };
    curve25519_dalek::edwards::CompressedEdwardsY(encoded)
        .decompress()
        .is_some_and(|point| point.compress().to_bytes() == encoded && !point.is_small_order())
}

fn validate_ec_public_key(object: &serde_json::Map<String, Value>) -> Result<(), DidJwkError> {
    use reallyme_crypto::operations::key_encoding::{
        decompress_p256_public_key, decompress_p384_public_key, decompress_p521_public_key,
        decompress_secp256k1_public_key,
    };

    let x = decode_base64url_member(object, "x")?;
    let y = decode_base64url_member(object, "y")?;
    let expected_coordinate_len = match object.get("crv").and_then(Value::as_str) {
        Some("P-256" | "secp256k1") => 32,
        Some("P-384") => 48,
        Some("P-521") => 66,
        _ => {
            return Err(DidJwkError::new(DidJwkErrorReason::InvalidPublicJwk));
        }
    };
    if x.len() != expected_coordinate_len || y.len() != expected_coordinate_len {
        return Err(DidJwkError::new(DidJwkErrorReason::InvalidPublicJwk));
    }
    let last_y = y
        .last()
        .copied()
        .ok_or(DidJwkError::new(DidJwkErrorReason::InvalidPublicJwk))?;
    let capacity = expected_coordinate_len
        .checked_add(1)
        .ok_or(DidJwkError::new(DidJwkErrorReason::InvalidPublicJwk))?;
    let mut compressed = Vec::with_capacity(capacity);
    compressed.push(if last_y & 1 == 0 { 0x02 } else { 0x03 });
    compressed.extend_from_slice(&x);

    let valid = match object.get("crv").and_then(Value::as_str) {
        Some("P-256") => decompress_p256_public_key(&compressed).is_ok_and(|point| {
            point.get(1..33) == Some(x.as_slice()) && point.get(33..65) == Some(y.as_slice())
        }),
        Some("P-384") => decompress_p384_public_key(&compressed).is_ok_and(|point| {
            point.get(1..49) == Some(x.as_slice()) && point.get(49..97) == Some(y.as_slice())
        }),
        Some("P-521") => decompress_p521_public_key(&compressed).is_ok_and(|point| {
            point.get(1..67) == Some(x.as_slice()) && point.get(67..133) == Some(y.as_slice())
        }),
        Some("secp256k1") => decompress_secp256k1_public_key(&compressed)
            .is_ok_and(|(validated_x, validated_y)| validated_x == x && validated_y == y),
        _ => false,
    };
    valid
        .then_some(())
        .ok_or(DidJwkError::new(DidJwkErrorReason::InvalidPublicJwk))
}

fn validate_rsa_public_key(object: &serde_json::Map<String, Value>) -> Result<(), DidJwkError> {
    let modulus = decode_base64url_member(object, "n")?;
    let exponent = decode_base64url_member(object, "e")?;
    let canonical_uint = |value: &[u8]| {
        !value.is_empty() && value.first() != Some(&0) && value.iter().any(|byte| *byte != 0)
    };
    let exponent_is_valid = canonical_uint(&exponent)
        && exponent.len() <= MAX_RSA_EXPONENT_BYTES
        && exponent.last().is_some_and(|byte| byte & 1 == 1)
        && !(exponent.len() == 1 && exponent.first().is_some_and(|value| *value < 3));
    let modulus_bits = unsigned_integer_bits(&modulus)?;
    let modulus_is_odd = modulus.last().is_some_and(|byte| byte & 1 == 1);
    if canonical_uint(&modulus)
        && modulus_is_odd
        && (MIN_RSA_MODULUS_BITS..=MAX_RSA_MODULUS_BITS).contains(&modulus_bits)
        && exponent_is_valid
    {
        Ok(())
    } else {
        Err(DidJwkError::new(DidJwkErrorReason::InvalidPublicJwk))
    }
}

fn unsigned_integer_bits(value: &[u8]) -> Result<usize, DidJwkError> {
    let first = value
        .first()
        .copied()
        .ok_or(DidJwkError::new(DidJwkErrorReason::InvalidPublicJwk))?;
    let leading_zero_bits = usize::try_from(first.leading_zeros())
        .map_err(|_| DidJwkError::new(DidJwkErrorReason::InvalidPublicJwk))?;
    value
        .len()
        .checked_mul(BITS_PER_BYTE)
        .and_then(|bits| bits.checked_sub(leading_zero_bits))
        .ok_or(DidJwkError::new(DidJwkErrorReason::InvalidPublicJwk))
}

fn validate_akp_public_key(object: &serde_json::Map<String, Value>) -> Result<(), DidJwkError> {
    let public_key = decode_base64url_member(object, "pub")?;
    let algorithm = object
        .get("alg")
        .and_then(Value::as_str)
        .ok_or(DidJwkError::new(DidJwkErrorReason::InvalidPublicJwk))?;

    // RFC 9964 fixes the public-key size for each registered ML-DSA algorithm.
    // AKP is deliberately extensible, so structurally valid keys for other
    // algorithms remain resolvable rather than being rejected as unknown.
    let expected_len = match algorithm {
        "ML-DSA-44" => Some(ML_DSA_44_PUBLIC_KEY_LEN),
        "ML-DSA-65" => Some(ML_DSA_65_PUBLIC_KEY_LEN),
        "ML-DSA-87" => Some(ML_DSA_87_PUBLIC_KEY_LEN),
        _ => None,
    };
    if expected_len.is_none_or(|expected_len| public_key.len() == expected_len) {
        Ok(())
    } else {
        Err(DidJwkError::new(DidJwkErrorReason::InvalidPublicJwk))
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
