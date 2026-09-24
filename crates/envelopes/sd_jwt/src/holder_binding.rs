// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_codec::base64url::bytes_to_base64url;
use reallyme_crypto::core::HashAlgorithm;
use reallyme_crypto::dispatch::hash_digest;
use reallyme_crypto::jwk::Jwk;
use reallyme_crypto::operations::constant_time::equal as constant_time_equal;
use reallyme_jose::jwt::{
    decode_verify_jwt_with_claims_validation_and_header_validation,
    encode_signed_jwt_with_header_options, JwtClaimsValidationPolicy, JwtHeaderEncodeOptions,
    JwtHeaderValidationOptions, JwtTemporalValidationPolicy,
};
use serde_json::json;
use serde_json::Value;
use zeroize::{Zeroize, Zeroizing};

use crate::{serialize_sd_jwt_compact, SdJwtEnvelopeError};

const KEY_BINDING_TYP_VALUES: &[&str] = &["kb+jwt"];
const SD_HASH_CLAIM_NAME: &str = "sd_hash";
const AUDIENCE_CLAIM_NAME: &str = "aud";
const NONCE_CLAIM_NAME: &str = "nonce";
// A verifier may choose a shorter freshness window, but never a bearer-like
// multi-day lifetime through accidental policy configuration.
const MAX_KB_JWT_AGE_SECONDS: u64 = 86_400;
const MAX_KB_JWT_FUTURE_IAT_SKEW_SECONDS: u64 = 300;

#[derive(Debug, Clone, Copy)]
pub struct KeyBindingVerificationOptions<'a> {
    pub holder_jwk: &'a Jwk,
    pub holder_public_key: &'a [u8],
    pub expected_audience: &'a str,
    pub expected_nonce: &'a str,
    pub now_unix: u64,
    /// Maximum accepted future skew for the mandatory `iat` claim.
    pub max_future_iat_skew_seconds: u64,
    /// Maximum age accepted for the mandatory KB-JWT `iat` claim.
    pub max_iat_age_seconds: u64,
}

#[derive(Debug, Clone, Copy)]
pub struct KeyBindingJwtBuildOptions<'a> {
    pub holder_jwk: &'a Jwk,
    pub holder_private_key: &'a [u8],
    pub audience: &'a str,
    pub nonce: &'a str,
    pub issued_at_unix: u64,
}

pub fn build_key_binding_jwt(
    issuer_signed_jwt: &str,
    disclosures: &[String],
    options: &KeyBindingJwtBuildOptions<'_>,
) -> Result<String, SdJwtEnvelopeError> {
    if options.audience.is_empty() || options.nonce.is_empty() || options.issued_at_unix == 0 {
        return Err(SdJwtEnvelopeError::InvalidKeyBindingJwt);
    }

    let compact_without_kb = serialize_sd_jwt_compact(issuer_signed_jwt, disclosures)?;
    let sd_hash = bytes_to_base64url(&hash_digest(
        HashAlgorithm::Sha2_256,
        compact_without_kb.as_bytes(),
    )?);

    let payload = json!({
        SD_HASH_CLAIM_NAME: sd_hash,
        AUDIENCE_CLAIM_NAME: options.audience,
        NONCE_CLAIM_NAME: options.nonce,
        "iat": options.issued_at_unix,
    });

    encode_signed_jwt_with_header_options(
        &payload,
        options.holder_jwk,
        options.holder_private_key,
        &JwtHeaderEncodeOptions::new(Some("kb+jwt".to_owned())),
    )
    .map_err(SdJwtEnvelopeError::from)
}

pub(crate) fn verify_key_binding_jwt(
    issuer_signed_jwt: &str,
    disclosures: &[String],
    key_binding_jwt: &str,
    options: &KeyBindingVerificationOptions<'_>,
) -> Result<Value, SdJwtEnvelopeError> {
    if options.now_unix == 0
        || options.max_future_iat_skew_seconds > MAX_KB_JWT_FUTURE_IAT_SKEW_SECONDS
    {
        return Err(SdJwtEnvelopeError::InvalidKeyBindingJwt);
    }
    let temporal_policy = JwtTemporalValidationPolicy::new(
        false,
        false,
        true,
        0,
        options.max_future_iat_skew_seconds,
    );
    let claims_policy =
        JwtClaimsValidationPolicy::new(temporal_policy, options.expected_audience, None, None);
    let payload: Value = decode_verify_jwt_with_claims_validation_and_header_validation(
        key_binding_jwt,
        options.holder_jwk,
        options.holder_public_key,
        options.now_unix,
        claims_policy,
        &JwtHeaderValidationOptions::new(false, false, KEY_BINDING_TYP_VALUES),
    )?;

    if options.max_iat_age_seconds == 0 || options.max_iat_age_seconds > MAX_KB_JWT_AGE_SECONDS {
        return Err(SdJwtEnvelopeError::InvalidKeyBindingJwt);
    }
    let issued_at = payload
        .get("iat")
        .and_then(Value::as_u64)
        .ok_or(SdJwtEnvelopeError::InvalidKeyBindingJwt)?;
    let stale_after = issued_at
        .checked_add(options.max_iat_age_seconds)
        .ok_or(SdJwtEnvelopeError::InvalidKeyBindingJwt)?;
    if stale_after < options.now_unix {
        return Err(SdJwtEnvelopeError::InvalidKeyBindingJwt);
    }

    let compact_without_kb = serialize_sd_jwt_compact(issuer_signed_jwt, disclosures)?;
    let expected_sd_hash = bytes_to_base64url(&hash_digest(
        HashAlgorithm::Sha2_256,
        compact_without_kb.as_bytes(),
    )?);

    let object = payload
        .as_object()
        .ok_or(SdJwtEnvelopeError::InvalidKeyBindingJwt)?;
    if object
        .get(SD_HASH_CLAIM_NAME)
        .and_then(Value::as_str)
        .filter(|value| constant_time_equal(value.as_bytes(), expected_sd_hash.as_bytes()))
        .is_none()
    {
        return Err(SdJwtEnvelopeError::InvalidKeyBindingJwt);
    }
    if object
        .get(NONCE_CLAIM_NAME)
        .and_then(Value::as_str)
        .filter(|value| constant_time_equal(value.as_bytes(), options.expected_nonce.as_bytes()))
        .is_none()
    {
        return Err(SdJwtEnvelopeError::InvalidKeyBindingJwt);
    }

    Ok(payload)
}

pub(crate) fn validate_key_binding_confirmation(
    issuer_payload: &Value,
    options: &KeyBindingVerificationOptions<'_>,
) -> Result<(), SdJwtEnvelopeError> {
    let confirmation_jwk = issuer_payload
        .get("cnf")
        .and_then(Value::as_object)
        .and_then(|confirmation| confirmation.get("jwk"))
        .ok_or(SdJwtEnvelopeError::InvalidKeyBindingJwt)?;
    let confirmation_jwk: Jwk = serde_json::from_value(confirmation_jwk.clone())
        .map_err(|_| SdJwtEnvelopeError::InvalidKeyBindingJwt)?;
    let confirmation_public_key = confirmation_jwk
        .public_key_bytes()
        .map_err(|_| SdJwtEnvelopeError::InvalidKeyBindingJwt)?;
    let supplied_jwk_public_key = options
        .holder_jwk
        .public_key_bytes()
        .map_err(|_| SdJwtEnvelopeError::InvalidKeyBindingJwt)?;

    // RFC 9901 §§4.1.2 and 7.3 bind KB-JWT verification to the key fixed by
    // the issuer-signed `cnf` claim. Validating both the JWK and raw-key views
    // prevents a caller from supplying internally inconsistent key material.
    let confirmation_thumbprint = jwk_thumbprint_sha256(&confirmation_jwk)?;
    let supplied_thumbprint = jwk_thumbprint_sha256(options.holder_jwk)?;
    if !constant_time_equal(&confirmation_thumbprint, &supplied_thumbprint)
        || !constant_time_equal(
            confirmation_public_key.as_slice(),
            options.holder_public_key,
        )
        || !constant_time_equal(
            supplied_jwk_public_key.as_slice(),
            options.holder_public_key,
        )
    {
        return Err(SdJwtEnvelopeError::InvalidKeyBindingJwt);
    }

    Ok(())
}

fn jwk_thumbprint_sha256(jwk: &Jwk) -> Result<[u8; 32], SdJwtEnvelopeError> {
    let value = serde_json::to_value(jwk).map_err(|_| SdJwtEnvelopeError::InvalidKeyBindingJwt)?;
    let object = value
        .as_object()
        .ok_or(SdJwtEnvelopeError::InvalidKeyBindingJwt)?;
    let key_type = object
        .get("kty")
        .and_then(Value::as_str)
        .ok_or(SdJwtEnvelopeError::InvalidKeyBindingJwt)?;
    let required_members: &[&str] = match key_type {
        "EC" => &["crv", "kty", "x", "y"],
        "OKP" => &["crv", "kty", "x"],
        "RSA" => &["e", "kty", "n"],
        _ => return Err(SdJwtEnvelopeError::InvalidKeyBindingJwt),
    };
    let mut canonical = serde_json::Map::new();
    for member in required_members {
        let member_value = object
            .get(*member)
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or(SdJwtEnvelopeError::InvalidKeyBindingJwt)?;
        canonical.insert((*member).to_owned(), Value::String(member_value.to_owned()));
    }
    let mut encoded = Zeroizing::new(
        serde_json::to_vec(&Value::Object(canonical))
            .map_err(|_| SdJwtEnvelopeError::InvalidKeyBindingJwt)?,
    );
    let mut digest = hash_digest(HashAlgorithm::Sha2_256, &encoded)?;
    encoded.zeroize();
    let result = <[u8; 32]>::try_from(digest.as_slice())
        .map_err(|_| SdJwtEnvelopeError::InvalidKeyBindingJwt);
    digest.zeroize();
    result
}
