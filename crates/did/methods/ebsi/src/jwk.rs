// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Public JWK policy for legal-entity did:ebsi verification methods.

use serde_json::Value;

use crate::{DidEbsiError, DidEbsiErrorReason};

const PRIVATE_JWK_MEMBERS: [&str; 8] = ["d", "p", "q", "dp", "dq", "qi", "oth", "k"];
const P256_COORDINATE_BASE64URL_BYTES: usize = 43;

pub(crate) fn validate_public_jwk(
    value: Option<&Value>,
    method_id: &str,
) -> Result<(), DidEbsiError> {
    let jwk = value
        .and_then(Value::as_object)
        .ok_or(DidEbsiError::new(DidEbsiErrorReason::InvalidDocument))?;
    if PRIVATE_JWK_MEMBERS
        .iter()
        .any(|name| jwk.contains_key(*name))
    {
        return Err(DidEbsiError::new(DidEbsiErrorReason::InvalidDocument));
    }
    if jwk.get("kty").and_then(Value::as_str) != Some("EC")
        || jwk.get("crv").and_then(Value::as_str) != Some("P-256")
        || jwk.get("alg").and_then(Value::as_str) != Some("ES256")
    {
        return Err(DidEbsiError::new(DidEbsiErrorReason::UnsupportedAlgorithm));
    }
    if !jwk
        .get("x")
        .and_then(Value::as_str)
        .is_some_and(valid_p256_coordinate)
        || !jwk
            .get("y")
            .and_then(Value::as_str)
            .is_some_and(valid_p256_coordinate)
    {
        return Err(DidEbsiError::new(DidEbsiErrorReason::InvalidDocument));
    }
    if jwk
        .get("use")
        .is_some_and(|value| value.as_str() != Some("sig"))
        || !valid_key_operations(jwk.get("key_ops"))
    {
        return Err(DidEbsiError::new(DidEbsiErrorReason::InvalidKeyUsage));
    }
    if let Some(key_id) = jwk.get("kid") {
        let fragment = method_id.split_once('#').map(|(_, value)| value);
        if key_id.as_str() != fragment {
            return Err(DidEbsiError::new(DidEbsiErrorReason::InvalidDocument));
        }
    }
    Ok(())
}

fn valid_key_operations(value: Option<&Value>) -> bool {
    let Some(value) = value else {
        return true;
    };
    matches!(value, Value::Array(values) if values.len() == 1 && values.first().and_then(Value::as_str) == Some("verify"))
}

fn valid_p256_coordinate(value: &str) -> bool {
    value.len() == P256_COORDINATE_BASE64URL_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        // A 32-byte coordinate has two unused base64url bits. Restricting the
        // final sextet ensures there is one canonical unpadded representation.
        && value.as_bytes().last().is_some_and(|last| {
            matches!(
                last,
                b'A' | b'E'
                    | b'I'
                    | b'M'
                    | b'Q'
                    | b'U'
                    | b'Y'
                    | b'c'
                    | b'g'
                    | b'k'
                    | b'o'
                    | b's'
                    | b'w'
                    | b'0'
                    | b'4'
                    | b'8'
            )
        })
}
