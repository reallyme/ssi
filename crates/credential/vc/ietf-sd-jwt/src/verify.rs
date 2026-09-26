// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use core::fmt;
use std::collections::BTreeMap;

use envelopes_jwk::Jwk;
use envelopes_jwt::jwt::{
    decode_verify_jwt_signature_only_with_header_validation, JwtHeaderValidationOptions,
};
use serde_json::Value;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::IetfSdJwtVcError;
use crate::payload::SdJwtDisclosure;
use crate::process_disclosures::{process_sd_jwt_disclosures, DisclosureContent};
use crate::sensitive::{
    zeroize_json_btree, zeroize_json_value, zeroize_strings, MAX_COMPACT_SD_JWT_BYTES,
    MAX_SD_JWT_DISCLOSURES, MAX_SD_JWT_DISCLOSURE_BYTES,
};
use crate::validate_temporal_claims::{
    validate_credential_temporal_claims, IetfSdJwtTemporalPolicy,
};

pub struct VerifiedIetfSdJwtVc {
    pub payload: Value,
    pub disclosed_claims: BTreeMap<String, Value>,
    pub disclosures: Vec<SdJwtDisclosure>,
    pub kb_jwt: Option<String>,
}

impl fmt::Debug for VerifiedIetfSdJwtVc {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("VerifiedIetfSdJwtVc([REDACTED])")
    }
}

impl Zeroize for VerifiedIetfSdJwtVc {
    fn zeroize(&mut self) {
        zeroize_json_value(&mut self.payload);
        zeroize_json_btree(&mut self.disclosed_claims);
        for disclosure in &mut self.disclosures {
            disclosure.zeroize();
        }
        self.disclosures.clear();
        if let Some(value) = &mut self.kb_jwt {
            value.zeroize();
        }
        self.kb_jwt = None;
    }
}

impl Drop for VerifiedIetfSdJwtVc {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for VerifiedIetfSdJwtVc {}

pub fn verify_ietf_sd_jwt_vc(
    compact_sd_jwt: &str,
    issuer_jwk: &Jwk,
    issuer_public_key: &[u8],
    temporal_policy: &IetfSdJwtTemporalPolicy,
) -> Result<VerifiedIetfSdJwtVc, IetfSdJwtVcError> {
    temporal_policy.validate()?;
    let parsed = parse_compact_sd_jwt(compact_sd_jwt)?;

    let payload =
        verify_issuer_signed_jwt(&parsed.issuer_signed_jwt, issuer_jwk, issuer_public_key)?;
    let payload_obj = payload.as_object().ok_or(IetfSdJwtVcError::InvalidInput)?;

    if payload_obj.contains_key("cnf") || parsed.kb_jwt.is_some() {
        // This legacy entry point verifies only issuer integrity and
        // disclosures; it has no verifier audience, nonce, or holder key
        // input. RFC 9901 §§3.3, 4.1.2, 4.3, and 7.3 therefore prohibit
        // treating holder-bound input as verified here. Callers must use
        // `verify_rfc9901_sd_jwt` for SD-JWT+KB verification.
        return Err(IetfSdJwtVcError::MissingKeyBinding);
    }

    let mut processed = process_sd_jwt_disclosures(&payload, &parsed.disclosures)?;
    validate_credential_temporal_claims(&payload, &processed.resolved, temporal_policy)?;

    let disclosed_claims = match core::mem::take(&mut processed.resolved) {
        Value::Object(claims) => claims.into_iter().collect::<BTreeMap<String, Value>>(),
        mut other => {
            zeroize_json_value(&mut other);
            return Err(IetfSdJwtVcError::InvalidInput);
        }
    };
    let mut disclosures = Vec::with_capacity(processed.disclosures.len());
    for disclosure in &mut processed.disclosures {
        if let DisclosureContent::ObjectProperty { name, value } = &mut disclosure.content {
            disclosures.push(SdJwtDisclosure {
                salt_b64u: core::mem::take(&mut disclosure.salt),
                key: core::mem::take(name),
                value: core::mem::take(value),
            });
        }
    }

    Ok(VerifiedIetfSdJwtVc {
        payload,
        disclosed_claims,
        disclosures,
        kb_jwt: None,
    })
}

struct ParsedCompactSdJwt {
    issuer_signed_jwt: String,
    disclosures: Vec<String>,
    kb_jwt: Option<String>,
}

impl Zeroize for ParsedCompactSdJwt {
    fn zeroize(&mut self) {
        self.issuer_signed_jwt.zeroize();
        zeroize_strings(&mut self.disclosures);
        if let Some(value) = &mut self.kb_jwt {
            value.zeroize();
        }
        self.kb_jwt = None;
    }
}

impl Drop for ParsedCompactSdJwt {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for ParsedCompactSdJwt {}

fn parse_compact_sd_jwt(compact: &str) -> Result<ParsedCompactSdJwt, IetfSdJwtVcError> {
    if compact.trim().is_empty() || compact.len() > MAX_COMPACT_SD_JWT_BYTES {
        return Err(IetfSdJwtVcError::InvalidCompactFormat);
    }

    if compact.split('~').count() > MAX_SD_JWT_DISCLOSURES + 2 {
        return Err(IetfSdJwtVcError::InvalidCompactFormat);
    }

    let parts: Vec<&str> = compact.split('~').collect();
    if parts.len() < 2 {
        return Err(IetfSdJwtVcError::InvalidCompactFormat);
    }

    let issuer_signed_jwt = parts[0].to_string();
    if issuer_signed_jwt.split('.').count() != 3 {
        return Err(IetfSdJwtVcError::InvalidCompactFormat);
    }

    let trailing_empty = parts.last().map(|s| s.is_empty()).unwrap_or(false);

    let mut disclosures = Vec::new();
    let mut kb_jwt = None;

    if trailing_empty {
        for p in &parts[1..parts.len() - 1] {
            if p.is_empty() {
                return Err(IetfSdJwtVcError::InvalidCompactFormat);
            }
            disclosures.push((*p).to_string());
        }
    } else {
        if parts.len() < 3 {
            return Err(IetfSdJwtVcError::InvalidCompactFormat);
        }
        for p in &parts[1..parts.len() - 1] {
            if p.is_empty() {
                return Err(IetfSdJwtVcError::InvalidCompactFormat);
            }
            disclosures.push((*p).to_string());
        }
        let final_part = parts[parts.len() - 1];
        if final_part.is_empty() {
            return Err(IetfSdJwtVcError::InvalidCompactFormat);
        }
        kb_jwt = Some(final_part.to_string());
    }

    if disclosures.len() > MAX_SD_JWT_DISCLOSURES
        || disclosures
            .iter()
            .any(|value| value.len() > MAX_SD_JWT_DISCLOSURE_BYTES)
        || kb_jwt
            .as_deref()
            .is_some_and(|value| value.split('.').count() != 3)
    {
        return Err(IetfSdJwtVcError::InvalidCompactFormat);
    }

    Ok(ParsedCompactSdJwt {
        issuer_signed_jwt,
        disclosures,
        kb_jwt,
    })
}

fn verify_issuer_signed_jwt(
    jwt: &str,
    issuer_jwk: &Jwk,
    issuer_public_key: &[u8],
) -> Result<Value, IetfSdJwtVcError> {
    decode_verify_jwt_signature_only_with_header_validation(
        jwt,
        issuer_jwk,
        issuer_public_key,
        &JwtHeaderValidationOptions::new(false, false, &["dc+sd-jwt"]),
    )
    .map_err(map_jwt_error)
}

fn map_jwt_error(err: envelopes_jwt::jwt::JwtError) -> IetfSdJwtVcError {
    match err {
        envelopes_jwt::jwt::JwtError::InvalidHeader => IetfSdJwtVcError::InvalidJwtHeader,
        envelopes_jwt::jwt::JwtError::InvalidSignature
        | envelopes_jwt::jwt::JwtError::KeyIdMismatch
        | envelopes_jwt::jwt::JwtError::PublicKeyMismatch
        | envelopes_jwt::jwt::JwtError::InvalidPublicKey
        | envelopes_jwt::jwt::JwtError::Crypto => IetfSdJwtVcError::Verification,
        envelopes_jwt::jwt::JwtError::UnsupportedAlgorithm => {
            IetfSdJwtVcError::UnsupportedAlgorithm
        }
        envelopes_jwt::jwt::JwtError::MissingAlgorithm => IetfSdJwtVcError::MissingAlgorithm,
        envelopes_jwt::jwt::JwtError::InvalidJwtFormat => IetfSdJwtVcError::InvalidCompactFormat,
        _ => IetfSdJwtVcError::InvalidInput,
    }
}
