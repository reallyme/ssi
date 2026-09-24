// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use core::fmt;
use std::collections::{BTreeMap, BTreeSet};

use crypto_sha2_256::digest as sha2_256_digest;
use envelopes_jwk::Jwk;
use envelopes_jwt::jwt::{
    decode_verify_jwt_signature_only_with_header_validation, JwtHeaderValidationOptions,
};
use serde_json::{Map, Value};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::IetfSdJwtVcError;
use crate::issue::{parse_sd_alg, IetfSdJwtHashAlgorithm};
use crate::payload::SdJwtDisclosure;
use crate::sensitive::{
    zeroize_json_btree, zeroize_json_value, zeroize_strings, MAX_COMPACT_SD_JWT_BYTES,
    MAX_SD_JWT_DISCLOSURES, MAX_SD_JWT_DISCLOSURE_BYTES,
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
) -> Result<VerifiedIetfSdJwtVc, IetfSdJwtVcError> {
    let parsed = parse_compact_sd_jwt(compact_sd_jwt)?;

    let payload =
        verify_issuer_signed_jwt(&parsed.issuer_signed_jwt, issuer_jwk, issuer_public_key)?;
    let payload_obj = payload.as_object().ok_or(IetfSdJwtVcError::InvalidInput)?;

    if payload_obj.contains_key("cnf") || parsed.kb_jwt.is_some() {
        // This legacy entry point verifies only issuer integrity and
        // disclosures; it has no verifier audience, nonce, time, or holder
        // key input. RFC 9901 §§3.3, 4.1.2, 4.3, and 7.3 therefore prohibit
        // treating holder-bound input as verified here. Callers must use
        // `verify_rfc9901_sd_jwt` for SD-JWT+KB verification.
        return Err(IetfSdJwtVcError::MissingKeyBinding);
    }

    let hash_alg = parse_sd_alg(payload_obj)?;
    let mut expected_digests = BTreeSet::new();
    collect_expected_digests(&payload, &mut expected_digests)?;
    if expected_digests.is_empty() && !parsed.disclosures.is_empty() {
        return Err(IetfSdJwtVcError::MissingSdClaim);
    }

    let mut pending: Vec<(String, Value)> = Vec::with_capacity(parsed.disclosures.len());
    for disclosure_b64u in &parsed.disclosures {
        let digest = hash_alg.digest_b64url(disclosure_b64u);
        let disclosure_json = decode_disclosure_json(disclosure_b64u)?;
        pending.push((digest, disclosure_json));
    }

    let mut accepted_disclosures = Vec::with_capacity(parsed.disclosures.len());
    let mut progress = true;
    while progress {
        progress = false;
        let mut next = Vec::new();

        for (digest, disclosure_json) in pending {
            if expected_digests.contains(&digest) {
                if let Some(arr) = disclosure_json.as_array() {
                    let nested = if arr.len() == 3 {
                        arr.get(2)
                    } else {
                        arr.get(1)
                    };
                    if let Some(v) = nested {
                        collect_expected_digests(v, &mut expected_digests)?;
                    }
                }
                accepted_disclosures.push((digest, disclosure_json));
                progress = true;
            } else {
                next.push((digest, disclosure_json));
            }
        }

        pending = next;
    }

    if !pending.is_empty() {
        return Err(IetfSdJwtVcError::DisclosureDigestMismatch);
    }

    let mut by_digest: BTreeMap<String, Value> = BTreeMap::new();
    for (digest, disclosure_json) in &accepted_disclosures {
        by_digest.insert(digest.clone(), disclosure_json.clone());
    }

    let resolved = resolve_value(&payload, &by_digest)?;
    let disclosed_claims = top_level_claims(&resolved)?;
    let disclosures = to_property_disclosures(&accepted_disclosures)?;

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

trait HashDigest {
    fn digest_b64url(&self, disclosure_b64u: &str) -> String;
}

impl HashDigest for IetfSdJwtHashAlgorithm {
    fn digest_b64url(&self, disclosure_b64u: &str) -> String {
        match self {
            IetfSdJwtHashAlgorithm::Sha256 => codec_base64url::bytes_to_base64url(
                sha2_256_digest(disclosure_b64u.as_bytes()).as_bytes(),
            ),
        }
    }
}

fn decode_disclosure_json(disclosure_b64u: &str) -> Result<Value, IetfSdJwtVcError> {
    let disclosure_bytes = codec_base64url::base64url_to_bytes(disclosure_b64u)
        .map_err(|_| IetfSdJwtVcError::InvalidDisclosure)?;
    let disclosure_json: Value = serde_json::from_slice(&disclosure_bytes)
        .map_err(|_| IetfSdJwtVcError::InvalidDisclosure)?;

    let arr = disclosure_json
        .as_array()
        .ok_or(IetfSdJwtVcError::InvalidDisclosure)?;
    if arr.len() != 2 && arr.len() != 3 {
        return Err(IetfSdJwtVcError::InvalidDisclosure);
    }

    if !arr
        .first()
        .and_then(Value::as_str)
        .map(|s| !s.trim().is_empty())
        .unwrap_or(false)
    {
        return Err(IetfSdJwtVcError::InvalidDisclosure);
    }

    if arr.len() == 3
        && !arr
            .get(1)
            .and_then(Value::as_str)
            .map(|s| !s.trim().is_empty())
            .unwrap_or(false)
    {
        return Err(IetfSdJwtVcError::InvalidDisclosure);
    }

    Ok(disclosure_json)
}

fn collect_expected_digests(
    value: &Value,
    out: &mut BTreeSet<String>,
) -> Result<(), IetfSdJwtVcError> {
    match value {
        Value::Object(map) => {
            if let Some(sd) = map.get("_sd") {
                let arr = sd.as_array().ok_or(IetfSdJwtVcError::InvalidSdClaim)?;
                for v in arr {
                    let s = v.as_str().ok_or(IetfSdJwtVcError::InvalidSdClaim)?;
                    if !out.insert(s.to_string()) {
                        return Err(IetfSdJwtVcError::InvalidSdClaim);
                    }
                }
            }

            if let Some(placeholder) = map.get("...") {
                let s = placeholder
                    .as_str()
                    .ok_or(IetfSdJwtVcError::InvalidSdClaim)?;
                if !out.insert(s.to_string()) {
                    return Err(IetfSdJwtVcError::InvalidSdClaim);
                }
            }

            for (k, v) in map {
                if k != "_sd" && k != "_sd_alg" && k != "..." {
                    collect_expected_digests(v, out)?;
                }
            }
        }
        Value::Array(arr) => {
            for v in arr {
                collect_expected_digests(v, out)?;
            }
        }
        _ => {}
    }

    Ok(())
}

fn resolve_value(
    value: &Value,
    disclosures_by_digest: &BTreeMap<String, Value>,
) -> Result<Value, IetfSdJwtVcError> {
    match value {
        Value::Object(map) => resolve_object(map, disclosures_by_digest),
        Value::Array(arr) => resolve_array(arr, disclosures_by_digest),
        _ => Ok(value.clone()),
    }
}

fn resolve_object(
    map: &Map<String, Value>,
    disclosures_by_digest: &BTreeMap<String, Value>,
) -> Result<Value, IetfSdJwtVcError> {
    let mut out = Map::new();

    for (k, v) in map {
        if k == "_sd" || k == "_sd_alg" || k == "..." {
            continue;
        }
        out.insert(k.clone(), resolve_value(v, disclosures_by_digest)?);
    }

    if let Some(sd) = map.get("_sd") {
        let arr = sd.as_array().ok_or(IetfSdJwtVcError::InvalidSdClaim)?;
        for digest_v in arr {
            let digest = digest_v.as_str().ok_or(IetfSdJwtVcError::InvalidSdClaim)?;
            if let Some(disclosure_json) = disclosures_by_digest.get(digest) {
                let disclosure_arr = disclosure_json
                    .as_array()
                    .ok_or(IetfSdJwtVcError::InvalidDisclosure)?;
                if disclosure_arr.len() != 3 {
                    return Err(IetfSdJwtVcError::InvalidDisclosure);
                }
                let key = disclosure_arr[1]
                    .as_str()
                    .ok_or(IetfSdJwtVcError::InvalidDisclosure)?;
                if key.trim().is_empty() {
                    return Err(IetfSdJwtVcError::InvalidDisclosure);
                }
                let resolved = resolve_value(&disclosure_arr[2], disclosures_by_digest)?;
                if out.insert(key.to_string(), resolved).is_some() {
                    return Err(IetfSdJwtVcError::DuplicateClaimKey);
                }
            }
        }
    }

    Ok(Value::Object(out))
}

fn resolve_array(
    arr: &[Value],
    disclosures_by_digest: &BTreeMap<String, Value>,
) -> Result<Value, IetfSdJwtVcError> {
    let mut out = Vec::with_capacity(arr.len());

    for item in arr {
        if let Some(placeholder_digest) = item
            .as_object()
            .and_then(|m| m.get("..."))
            .and_then(Value::as_str)
        {
            if let Some(disclosure_json) = disclosures_by_digest.get(placeholder_digest) {
                let disclosure_arr = disclosure_json
                    .as_array()
                    .ok_or(IetfSdJwtVcError::InvalidDisclosure)?;
                if disclosure_arr.len() != 2 {
                    return Err(IetfSdJwtVcError::InvalidDisclosure);
                }
                let resolved = resolve_value(&disclosure_arr[1], disclosures_by_digest)?;
                out.push(resolved);
            }
        } else {
            out.push(resolve_value(item, disclosures_by_digest)?);
        }
    }

    Ok(Value::Array(out))
}

fn top_level_claims(resolved: &Value) -> Result<BTreeMap<String, Value>, IetfSdJwtVcError> {
    let obj = resolved.as_object().ok_or(IetfSdJwtVcError::InvalidInput)?;
    let mut out = BTreeMap::new();
    for (k, v) in obj {
        if k != "_sd" && k != "_sd_alg" {
            out.insert(k.clone(), v.clone());
        }
    }
    Ok(out)
}

fn to_property_disclosures(
    accepted_disclosures: &[(String, Value)],
) -> Result<Vec<SdJwtDisclosure>, IetfSdJwtVcError> {
    let mut out = Vec::new();

    for (_, disclosure_json) in accepted_disclosures {
        let arr = disclosure_json
            .as_array()
            .ok_or(IetfSdJwtVcError::InvalidDisclosure)?;

        if arr.len() == 3 {
            out.push(SdJwtDisclosure {
                salt_b64u: arr[0]
                    .as_str()
                    .ok_or(IetfSdJwtVcError::InvalidDisclosure)?
                    .to_string(),
                key: arr[1]
                    .as_str()
                    .ok_or(IetfSdJwtVcError::InvalidDisclosure)?
                    .to_string(),
                value: arr[2].clone(),
            });
        }
    }

    Ok(out)
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

#[allow(dead_code)]
fn _clone_payload_map(payload: &Map<String, Value>) -> Map<String, Value> {
    payload.clone()
}
