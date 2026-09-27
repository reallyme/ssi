// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_codec::base64url::{base64url_to_bytes, bytes_to_base64url};
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

use crate::{serialize_sd_jwt_compact, SdJwtEnvelopeError, SdJwtHashAlgorithm};

const KEY_BINDING_TYP_VALUES: &[&str] = &["kb+jwt"];
const SD_HASH_CLAIM_NAME: &str = "sd_hash";
const AUDIENCE_CLAIM_NAME: &str = "aud";
const NONCE_CLAIM_NAME: &str = "nonce";
// A verifier may choose a shorter freshness window, but never a bearer-like
// multi-day lifetime through accidental policy configuration.
/// Maximum verifier-configured age for a key-binding JWT.
pub const MAX_KB_JWT_AGE_SECONDS: u64 = 86_400;
/// Maximum verifier-configured future `iat` skew for a key-binding JWT.
pub const MAX_KB_JWT_FUTURE_IAT_SKEW_SECONDS: u64 = 300;
const MAX_ISSUER_PAYLOAD_BYTES: usize = 262_144;

/// Options controlling key binding verification.
#[derive(Clone, Copy)]
pub struct KeyBindingVerificationOptions<'a> {
    /// Holder public JWK whose parameters identify the key-binding key.
    pub holder_jwk: &'a Jwk,
    /// Holder public-key bytes used to verify the key-binding signature.
    pub holder_public_key: &'a [u8],
    /// Audience value that the authenticated key-binding JWT must match exactly.
    pub expected_audience: &'a str,
    /// Verifier nonce that the authenticated key-binding JWT must match exactly.
    pub expected_nonce: &'a str,
    /// Verification time as seconds since the Unix epoch.
    pub now_unix: u64,
    /// Maximum accepted future skew for the mandatory `iat` claim.
    pub max_future_iat_skew_seconds: u64,
    /// Maximum age accepted for the mandatory KB-JWT `iat` claim.
    pub max_iat_age_seconds: u64,
}

impl core::fmt::Debug for KeyBindingVerificationOptions<'_> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("KeyBindingVerificationOptions([REDACTED])")
    }
}

impl KeyBindingVerificationOptions<'_> {
    /// Validate verifier-supplied policy before any signature work.
    ///
    /// Empty audience or nonce values would make replay-protection comparisons
    /// vacuous, and out-of-range time bounds would silently widen freshness.
    pub fn validate(&self) -> Result<(), SdJwtEnvelopeError> {
        if self.expected_audience.is_empty()
            || self.expected_nonce.is_empty()
            || self.now_unix == 0
            || self.max_future_iat_skew_seconds > MAX_KB_JWT_FUTURE_IAT_SKEW_SECONDS
            || self.max_iat_age_seconds == 0
            || self.max_iat_age_seconds > MAX_KB_JWT_AGE_SECONDS
        {
            return Err(SdJwtEnvelopeError::InvalidKeyBindingJwt);
        }
        Ok(())
    }
}

/// Options controlling key binding JWT build.
#[derive(Clone, Copy)]
pub struct KeyBindingJwtBuildOptions<'a> {
    /// Holder public JWK whose parameters identify the key-binding key.
    pub holder_jwk: &'a Jwk,
    /// Holder private-key bytes used only to create the key-binding signature.
    pub holder_private_key: &'a [u8],
    /// Audience bound into the key-binding JWT.
    pub audience: &'a str,
    /// Verifier nonce bound into the key-binding JWT.
    pub nonce: &'a str,
    /// Issuance time encoded as seconds since the Unix epoch.
    pub issued_at_unix: u64,
}

impl core::fmt::Debug for KeyBindingJwtBuildOptions<'_> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("KeyBindingJwtBuildOptions([REDACTED])")
    }
}

/// Build key binding JWT after validating all caller-supplied inputs.
pub fn build_key_binding_jwt(
    issuer_signed_jwt: &str,
    disclosures: &[String],
    options: &KeyBindingJwtBuildOptions<'_>,
) -> Result<String, SdJwtEnvelopeError> {
    if options.audience.is_empty() || options.nonce.is_empty() || options.issued_at_unix == 0 {
        return Err(SdJwtEnvelopeError::InvalidKeyBindingJwt);
    }

    let compact_without_kb = serialize_sd_jwt_compact(issuer_signed_jwt, disclosures)?;
    let hash_algorithm = hash_algorithm_from_issuer_jwt(issuer_signed_jwt)?;
    let sd_hash = bytes_to_base64url(&hash_digest(
        hash_algorithm.dispatch_algorithm(),
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
    .map_err(|_| SdJwtEnvelopeError::InvalidKeyBindingJwt)
}

pub(crate) fn verify_key_binding_jwt(
    issuer_signed_jwt: &str,
    disclosures: &[String],
    key_binding_jwt: &str,
    options: &KeyBindingVerificationOptions<'_>,
    hash_algorithm: SdJwtHashAlgorithm,
) -> Result<Value, SdJwtEnvelopeError> {
    options.validate()?;
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
    )
    .map_err(|_| SdJwtEnvelopeError::InvalidKeyBindingJwt)?;

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
        hash_algorithm.dispatch_algorithm(),
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

pub(crate) fn hash_algorithm_from_payload(
    issuer_payload: &Value,
) -> Result<SdJwtHashAlgorithm, SdJwtEnvelopeError> {
    match issuer_payload.get("_sd_alg") {
        Some(Value::String(value)) => SdJwtHashAlgorithm::parse(value),
        None => Ok(SdJwtHashAlgorithm::default_for_sd_jwt()),
        Some(_) => Err(SdJwtEnvelopeError::InvalidHashAlgorithmClaim),
    }
}

fn hash_algorithm_from_issuer_jwt(
    issuer_signed_jwt: &str,
) -> Result<SdJwtHashAlgorithm, SdJwtEnvelopeError> {
    let mut components = issuer_signed_jwt.split('.');
    let _protected = components
        .next()
        .ok_or(SdJwtEnvelopeError::InvalidIssuerJwt)?;
    let payload = components
        .next()
        .ok_or(SdJwtEnvelopeError::InvalidIssuerJwt)?;
    let _signature = components
        .next()
        .ok_or(SdJwtEnvelopeError::InvalidIssuerJwt)?;
    if components.next().is_some() || payload.len() > MAX_ISSUER_PAYLOAD_BYTES {
        return Err(SdJwtEnvelopeError::InvalidIssuerJwt);
    }
    let payload = Zeroizing::new(
        base64url_to_bytes(payload).map_err(|_| SdJwtEnvelopeError::InvalidIssuerJwt)?,
    );
    if payload.len() > MAX_ISSUER_PAYLOAD_BYTES {
        return Err(SdJwtEnvelopeError::InvalidIssuerJwt);
    }
    let value: Value =
        serde_json::from_slice(&payload).map_err(|_| SdJwtEnvelopeError::InvalidIssuerJwt)?;
    hash_algorithm_from_payload(&value)
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
    // RFC 9901 §§4.1.2 and 7.3 bind KB-JWT verification to the key fixed by
    // the issuer-signed `cnf` claim. The thumbprint binds the supplied JWK to
    // the confirmation JWK; the raw comparison then binds the caller's actual
    // verification bytes to that authenticated confirmation key.
    let confirmation_thumbprint = jwk_thumbprint_sha256(&confirmation_jwk)?;
    let supplied_thumbprint = jwk_thumbprint_sha256(options.holder_jwk)?;
    if !constant_time_equal(&confirmation_thumbprint, &supplied_thumbprint) {
        return Err(SdJwtEnvelopeError::InvalidKeyBindingJwt);
    }
    if !constant_time_equal(
        confirmation_public_key.as_slice(),
        options.holder_public_key,
    ) {
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
