// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Public JWK policy for legal-entity did:ebsi verification methods.

use reallyme_did_method_jwk::{validate_public_jwk as validate_did_jwk, DidJwkErrorReason};
use serde_json::Value;

use crate::{DidEbsiError, DidEbsiErrorReason};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct EbsiJwkPurposes {
    pub(crate) signature: bool,
    pub(crate) key_agreement: bool,
}

pub(crate) fn validate_public_jwk(
    value: Option<&Value>,
    method_id: &str,
) -> Result<EbsiJwkPurposes, DidEbsiError> {
    let value = value.ok_or(DidEbsiError::new(DidEbsiErrorReason::InvalidDocument))?;
    let jwk = value
        .as_object()
        .ok_or(DidEbsiError::new(DidEbsiErrorReason::InvalidDocument))?;
    let curve = jwk.get("crv").and_then(Value::as_str);
    let algorithm = jwk.get("alg").and_then(Value::as_str);
    let profile_algorithm_is_valid = matches!(
        (curve, algorithm),
        (Some("P-256"), None | Some("ES256")) | (Some("secp256k1"), None | Some("ES256K"))
    );
    if jwk.get("kty").and_then(Value::as_str) != Some("EC") || !profile_algorithm_is_valid {
        return Err(DidEbsiError::new(DidEbsiErrorReason::UnsupportedAlgorithm));
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
    validate_did_jwk(value).map_err(|error| {
        let reason = match error.reason {
            DidJwkErrorReason::PrivateKeyMaterial => DidEbsiErrorReason::InvalidDocument,
            DidJwkErrorReason::InvalidPublicJwk
            | DidJwkErrorReason::InvalidJson
            | DidJwkErrorReason::InvalidBase64Url
            | DidJwkErrorReason::InvalidPrefix
            | DidJwkErrorReason::EmptyIdentifier
            | DidJwkErrorReason::SerializationFailed => DidEbsiErrorReason::InvalidDocument,
            _ => DidEbsiErrorReason::InvalidDocument,
        };
        DidEbsiError::new(reason)
    })?;
    Ok(EbsiJwkPurposes {
        signature: true,
        key_agreement: false,
    })
}

fn valid_key_operations(value: Option<&Value>) -> bool {
    let Some(value) = value else {
        return true;
    };
    matches!(value, Value::Array(values) if values.len() == 1 && values.first().and_then(Value::as_str) == Some("verify"))
}
