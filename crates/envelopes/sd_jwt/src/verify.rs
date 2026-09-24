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
    validate_key_binding_confirmation, verify_key_binding_jwt, KeyBindingVerificationOptions,
};
use crate::sensitive::{zeroize_json_value, zeroize_strings};
use crate::{
    parse_sd_jwt_json_serialization, parse_sd_jwt_or_kb_compact, process_sd_jwt_payload,
    SdJwtEnvelopeError, SdJwtOrKbCompact, SdJwtProcessingPolicy,
};

const DEFAULT_ISSUER_TYP_VALUES: &[&str] = &["dc+sd-jwt"];

#[derive(Debug, Clone, Copy)]
pub struct SdJwtVerificationOptions<'a> {
    pub issuer_allow_missing_typ: bool,
    /// Permit an authenticated embedded `jwk` or `x5c` header while still
    /// verifying exclusively with the caller-supplied issuer key material.
    pub issuer_allow_embedded_key_header: bool,
    pub issuer_accepted_typ_values: &'a [&'a str],
    pub processing_policy: SdJwtProcessingPolicy,
    pub require_key_binding: bool,
    pub key_binding: Option<KeyBindingVerificationOptions<'a>>,
}

impl Default for SdJwtVerificationOptions<'_> {
    fn default() -> Self {
        SdJwtVerificationOptions {
            issuer_allow_missing_typ: false,
            issuer_allow_embedded_key_header: false,
            issuer_accepted_typ_values: DEFAULT_ISSUER_TYP_VALUES,
            processing_policy: SdJwtProcessingPolicy::default(),
            require_key_binding: false,
            key_binding: None,
        }
    }
}

#[derive(PartialEq)]
pub struct VerifiedSdJwt {
    pub issuer_signed_jwt: String,
    pub issuer_payload: Value,
    pub resolved_payload: Value,
    pub disclosures: Vec<String>,
    pub key_binding_jwt: Option<String>,
    pub key_binding_payload: Option<Value>,
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

pub fn verify_sd_jwt(
    compact: &str,
    issuer_jwk: &Jwk,
    issuer_public_key: &[u8],
    options: &SdJwtVerificationOptions<'_>,
) -> Result<VerifiedSdJwt, SdJwtEnvelopeError> {
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
    )?;

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

    let resolved_payload = process_sd_jwt_payload(
        issuer_payload.clone(),
        &disclosures,
        options.processing_policy,
    )?;

    let key_binding_payload = match (&key_binding_jwt, options.key_binding) {
        (Some(kb_jwt), Some(kb_options)) => {
            if issuer_requires_key_binding {
                validate_key_binding_confirmation(&issuer_payload, &kb_options)?;
            }
            Some(verify_key_binding_jwt(
                &issuer_signed_jwt,
                &disclosures,
                kb_jwt,
                &kb_options,
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

pub fn verify_sd_jwt_json_serialization(
    input: &str,
    issuer_jwk: &Jwk,
    issuer_public_key: &[u8],
    options: &SdJwtVerificationOptions<'_>,
) -> Result<Vec<VerifiedSdJwt>, SdJwtEnvelopeError> {
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
