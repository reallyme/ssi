// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use core::fmt;

use reallyme_crypto::jwk::Jwk;
use reallyme_jose::jwt::{
    decode_verify_jwt_signature_only_with_header_validation, JwtHeaderValidationOptions,
};
use serde_json::Value;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::holder_binding::{
    hash_algorithm_from_payload, validate_key_binding_confirmation, verify_key_binding_jwt,
    KeyBindingVerificationOptions,
};
use crate::present::resolve_sd_jwt_payload;
use crate::sensitive::{zeroize_json_value, zeroize_strings};
use crate::validate_temporal_claims::{
    validate_credential_temporal_claims, DEFAULT_SD_JWT_CLOCK_SKEW_SECONDS,
    MAX_SD_JWT_CLOCK_SKEW_SECONDS,
};
use crate::{
    parse_sd_jwt_json_serialization, parse_sd_jwt_or_kb_compact, SdJwtEnvelopeError,
    SdJwtOrKbCompact, SdJwtProcessingPolicy,
};

const DEFAULT_ISSUER_TYP_VALUES: &[&str] = &["dc+sd-jwt"];

/// Policy and transaction context for SD-JWT verification.
#[derive(Debug, Clone, Copy)]
pub struct SdJwtVerificationOptions<'a> {
    /// Whether an otherwise valid issuer JWT may omit its protected `typ` value.
    pub issuer_allow_missing_typ: bool,
    /// Permit an authenticated embedded `jwk` or `x5c` header while still
    /// verifying exclusively with the caller-supplied issuer key material.
    pub issuer_allow_embedded_key_header: bool,
    /// Accepted protected `typ` values for the issuer-signed JWT.
    pub issuer_accepted_typ_values: &'a [&'a str],
    /// Resource limits applied while resolving recursive disclosures.
    pub processing_policy: SdJwtProcessingPolicy,
    /// Whether verification requires a valid holder key-binding JWT.
    pub require_key_binding: bool,
    /// Expected holder key and transaction binding used to verify a key-binding JWT.
    pub key_binding: Option<KeyBindingVerificationOptions<'a>>,
    /// Verifier clock as Unix seconds. Required; zero is rejected so an
    /// unset clock can never disable `exp`, `nbf`, or `iat` validation.
    pub now_unix: u64,
    /// Symmetric leeway for credential temporal claims, bounded by
    /// [`MAX_SD_JWT_CLOCK_SKEW_SECONDS`].
    pub clock_skew_seconds: u64,
    /// Require an issuer-signed expiration time.
    pub require_exp: bool,
}

impl SdJwtVerificationOptions<'_> {
    /// Construct strict verification options evaluated at `now_unix`.
    #[must_use]
    pub fn new(now_unix: u64) -> Self {
        SdJwtVerificationOptions {
            issuer_allow_missing_typ: false,
            issuer_allow_embedded_key_header: false,
            issuer_accepted_typ_values: DEFAULT_ISSUER_TYP_VALUES,
            processing_policy: SdJwtProcessingPolicy::default(),
            require_key_binding: false,
            key_binding: None,
            now_unix,
            clock_skew_seconds: DEFAULT_SD_JWT_CLOCK_SKEW_SECONDS,
            require_exp: false,
        }
    }

    fn validate(&self) -> Result<(), SdJwtEnvelopeError> {
        if self.now_unix == 0
            || self.clock_skew_seconds > MAX_SD_JWT_CLOCK_SKEW_SECONDS
            || self.issuer_accepted_typ_values.is_empty()
        {
            return Err(SdJwtEnvelopeError::InvalidVerificationPolicy);
        }
        if let Some(key_binding) = &self.key_binding {
            key_binding.validate()?;
        }
        Ok(())
    }
}

/// Verified issuer payload, resolved claims, and optional holder binding.
#[derive(PartialEq)]
pub struct VerifiedSdJwt {
    /// Compact issuer-signed JWT whose signature authenticates the SD-JWT payload.
    issuer_signed_jwt: String,
    /// Authenticated claims decoded from the issuer-signed JWT.
    issuer_payload: Value,
    /// Claims reconstructed after applying every validated disclosure.
    resolved_payload: Value,
    /// Encoded disclosures carried by this SD-JWT value.
    disclosures: Vec<String>,
    /// Compact key-binding JWT that binds the presentation to its audience and nonce.
    key_binding_jwt: Option<String>,
    /// Optional key binding payload.
    key_binding_payload: Option<Value>,
}

impl VerifiedSdJwt {
    /// Borrow the authenticated compact issuer JWT.
    #[must_use]
    pub fn issuer_signed_jwt(&self) -> &str {
        &self.issuer_signed_jwt
    }

    /// Borrow the authenticated issuer payload.
    #[must_use]
    pub const fn issuer_payload(&self) -> &Value {
        &self.issuer_payload
    }

    /// Borrow the disclosure-resolved payload.
    #[must_use]
    pub const fn resolved_payload(&self) -> &Value {
        &self.resolved_payload
    }

    /// Borrow the authenticated encoded disclosures.
    #[must_use]
    pub fn disclosures(&self) -> &[String] {
        &self.disclosures
    }

    /// Borrow the authenticated key-binding JWT, when present.
    #[must_use]
    pub fn key_binding_jwt(&self) -> Option<&str> {
        self.key_binding_jwt.as_deref()
    }

    /// Borrow the authenticated key-binding payload, when present.
    #[must_use]
    pub const fn key_binding_payload(&self) -> Option<&Value> {
        self.key_binding_payload.as_ref()
    }
}

impl fmt::Debug for VerifiedSdJwt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("VerifiedSdJwt([REDACTED])")
    }
}

impl Zeroize for VerifiedSdJwt {
    fn zeroize(&mut self) {
        self.issuer_signed_jwt.zeroize();
        zeroize_json_value(&mut self.issuer_payload);
        zeroize_json_value(&mut self.resolved_payload);
        zeroize_strings(&mut self.disclosures);
        if let Some(value) = &mut self.key_binding_jwt {
            value.zeroize();
        }
        self.key_binding_jwt = None;
        if let Some(value) = &mut self.key_binding_payload {
            zeroize_json_value(value);
        }
        self.key_binding_payload = None;
    }
}

impl Drop for VerifiedSdJwt {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for VerifiedSdJwt {}

/// Verifies an SD-JWT and returns a typed failure for any rejected check.
pub fn verify_sd_jwt(
    compact: &str,
    issuer_jwk: &Jwk,
    issuer_public_key: &[u8],
    options: &SdJwtVerificationOptions<'_>,
) -> Result<VerifiedSdJwt, SdJwtEnvelopeError> {
    options.validate()?;
    let parsed = parse_sd_jwt_or_kb_compact(compact)?;
    let (issuer_signed_jwt, disclosures, key_binding_jwt) = match parsed {
        SdJwtOrKbCompact::SdJwt(mut sd_jwt) => (
            core::mem::take(&mut sd_jwt.issuer_signed_jwt),
            core::mem::take(&mut sd_jwt.disclosures),
            None,
        ),
        SdJwtOrKbCompact::SdJwtWithKb(mut sd_jwt) => (
            core::mem::take(&mut sd_jwt.issuer_signed_jwt),
            core::mem::take(&mut sd_jwt.disclosures),
            Some(core::mem::take(&mut sd_jwt.key_binding_jwt)),
        ),
    };

    if options.require_key_binding && key_binding_jwt.is_none() {
        return Err(SdJwtEnvelopeError::InvalidKeyBindingJwt);
    }

    let issuer_payload: Value = decode_verify_jwt_signature_only_with_header_validation(
        &issuer_signed_jwt,
        issuer_jwk,
        issuer_public_key,
        &JwtHeaderValidationOptions::new(
            options.issuer_allow_missing_typ,
            options.issuer_allow_embedded_key_header,
            options.issuer_accepted_typ_values,
        ),
    )
    .map_err(|_| SdJwtEnvelopeError::InvalidIssuerJwt)?;
    if issuer_typ_requires_vct(&issuer_signed_jwt)?
        && !issuer_payload.get("vct").is_some_and(Value::is_string)
    {
        return Err(SdJwtEnvelopeError::InvalidIssuerJwt);
    }
    let hash_algorithm = hash_algorithm_from_payload(&issuer_payload)?;

    let issuer_requires_key_binding = issuer_payload.get("cnf").is_some();
    if issuer_requires_key_binding
        && (!options.require_key_binding
            || key_binding_jwt.is_none()
            || options.key_binding.is_none())
    {
        // RFC 9901 §§3.3, 4.1.2, and 7.3: an issuer-signed `cnf` makes the
        // credential holder-bound. Caller configuration cannot safely demote
        // it to a bearer credential by omitting or stripping the KB-JWT.
        return Err(SdJwtEnvelopeError::InvalidKeyBindingJwt);
    }

    let resolved_payload =
        resolve_sd_jwt_payload(&issuer_payload, &disclosures, options.processing_policy)?;
    validate_credential_temporal_claims(
        &issuer_payload,
        &resolved_payload,
        options.now_unix,
        options.clock_skew_seconds,
        options.require_exp,
    )?;

    let key_binding_payload = match (&key_binding_jwt, options.key_binding) {
        (Some(kb_jwt), Some(kb_options)) => {
            // A KB-JWT is meaningful only when the issuer authenticated the
            // confirmation key. Accepting a caller-selected key without
            // `cnf` would let a presenter manufacture holder binding for a
            // bearer credential.
            validate_key_binding_confirmation(&issuer_payload, &kb_options)?;
            Some(verify_key_binding_jwt(
                &issuer_signed_jwt,
                &disclosures,
                kb_jwt,
                &kb_options,
                hash_algorithm,
            )?)
        }
        (Some(_), None) => {
            return Err(SdJwtEnvelopeError::InvalidKeyBindingJwt);
        }
        (None, _) => None,
    };

    Ok(VerifiedSdJwt {
        issuer_signed_jwt,
        issuer_payload,
        resolved_payload,
        disclosures,
        key_binding_jwt,
        key_binding_payload,
    })
}

fn issuer_typ_requires_vct(compact_jwt: &str) -> Result<bool, SdJwtEnvelopeError> {
    let encoded_header = compact_jwt
        .split('.')
        .next()
        .ok_or(SdJwtEnvelopeError::InvalidIssuerJwt)?;
    let header_bytes = reallyme_codec::base64url::base64url_to_bytes(encoded_header)
        .map_err(|_| SdJwtEnvelopeError::InvalidIssuerJwt)?;
    let header: Value =
        serde_json::from_slice(&header_bytes).map_err(|_| SdJwtEnvelopeError::InvalidIssuerJwt)?;
    Ok(matches!(
        header.get("typ").and_then(Value::as_str),
        Some("dc+sd-jwt" | "vc+sd-jwt")
    ))
}

/// Verifies an SD-JWT JSON serialization under the same policy as compact input.
pub fn verify_sd_jwt_json_serialization(
    input: &str,
    issuer_jwk: &Jwk,
    issuer_public_key: &[u8],
    options: &SdJwtVerificationOptions<'_>,
) -> Result<Vec<VerifiedSdJwt>, SdJwtEnvelopeError> {
    options.validate()?;
    let parsed = parse_sd_jwt_json_serialization(input)?;
    let mut verified = Vec::with_capacity(parsed.entries.len());
    for entry in parsed.entries {
        let compact = entry.to_compact()?;
        verified.push(verify_sd_jwt(
            &compact,
            issuer_jwk,
            issuer_public_key,
            options,
        )?);
    }

    Ok(verified)
}
