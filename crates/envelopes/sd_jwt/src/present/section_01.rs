// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use core::fmt;
use std::collections::{BTreeSet, HashMap, HashSet};

use reallyme_codec::base64url::{base64url_to_bytes, bytes_to_base64url};
use reallyme_crypto::core::{HashAlgorithm, RngOutputKind};
use reallyme_crypto::csprng::{generate_bytes, OsSecureRandom};
use reallyme_crypto::dispatch::hash_digest;
use reallyme_crypto::jwk::Jwk;
use reallyme_jose::jwt::{encode_signed_jwt_with_header_options, JwtHeaderEncodeOptions};
use serde_json::{Map, Value};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::disclose::{
    create_array_element_disclosure, create_object_property_disclosure, decode_disclosure,
    validate_object_claim_name, DisclosureKind, ARRAY_DIGEST_CLAIM_NAME, SD_CLAIM_NAME,
};
use crate::registered_claims::is_non_selectively_disclosable_claim;
use crate::sensitive::{zeroize_json_value, zeroize_strings};
use crate::{digest_disclosure, serialize_sd_jwt_compact, SdJwtEnvelopeError, SdJwtHashAlgorithm};

const SD_ALG_CLAIM_NAME: &str = "_sd_alg";
const DEFAULT_SALT_BYTES: usize = 16;
const DECOY_DIGEST_BYTES: usize = 32;
const DEFAULT_ISSUER_TYP: &str = "dc+sd-jwt";
const VC_ISSUER_TYP: &str = "vc+sd-jwt";
const JWT_TYP: &str = "JWT";
const DEFAULT_MAX_DEPTH: usize = 64;
const DEFAULT_MAX_NODES: usize = 16_384;
/// Hard ceiling applied to caller-supplied processing depth. Recursive
/// processing is bounded by this value regardless of policy configuration.
pub const MAX_SD_JWT_PROCESSING_DEPTH: usize = 128;
/// Hard ceiling applied to caller-supplied processing node budgets.
pub const MAX_SD_JWT_PROCESSING_NODES: usize = 131_072;

pub trait SdJwtSaltSource {
    fn next_salt(&mut self) -> Result<String, SdJwtEnvelopeError>;
    fn next_decoy_digest(&mut self) -> Result<String, SdJwtEnvelopeError>;
}

#[derive(Default)]
pub struct SecureRandomSaltSource {
    rng: OsSecureRandom,
}

impl SecureRandomSaltSource {
    pub fn new() -> Self {
        SecureRandomSaltSource {
            rng: OsSecureRandom,
        }
    }
}

impl SdJwtSaltSource for SecureRandomSaltSource {
    fn next_salt(&mut self) -> Result<String, SdJwtEnvelopeError> {
        let random = generate_bytes::<DEFAULT_SALT_BYTES>(&mut self.rng, RngOutputKind::Generic)?;
        Ok(bytes_to_base64url(random.as_bytes()))
    }

    fn next_decoy_digest(&mut self) -> Result<String, SdJwtEnvelopeError> {
        let random = generate_bytes::<DECOY_DIGEST_BYTES>(&mut self.rng, RngOutputKind::Generic)?;
        Ok(bytes_to_base64url(&hash_digest(
            HashAlgorithm::Sha2_256,
            random.as_bytes(),
        )?))
    }
}

#[derive(Clone, PartialEq, Eq)]
pub enum SdJwtDisclosureStrategy {
    None,
    TopLevel,
    AllLevels,
    JsonPaths(BTreeSet<String>),
}

impl fmt::Debug for SdJwtDisclosureStrategy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::None => formatter.write_str("None"),
            Self::TopLevel => formatter.write_str("TopLevel"),
            Self::AllLevels => formatter.write_str("AllLevels"),
            Self::JsonPaths(_) => formatter.write_str("JsonPaths([REDACTED])"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecoyPolicy {
    pub object_decoys: u8,
    pub array_decoys: u8,
}

impl DecoyPolicy {
    pub const fn none() -> Self {
        DecoyPolicy {
            object_decoys: 0,
            array_decoys: 0,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SdJwtIssuerType {
    DigitalCredentialSdJwt,
    VerifiableCredentialSdJwt,
    Jwt,
    Omit,
}

impl SdJwtIssuerType {
    fn header_value(self) -> Option<String> {
        match self {
            SdJwtIssuerType::DigitalCredentialSdJwt => Some(DEFAULT_ISSUER_TYP.to_owned()),
            SdJwtIssuerType::VerifiableCredentialSdJwt => Some(VC_ISSUER_TYP.to_owned()),
            SdJwtIssuerType::Jwt => Some(JWT_TYP.to_owned()),
            SdJwtIssuerType::Omit => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SdJwtIssuancePolicy {
    pub disclosure_strategy: SdJwtDisclosureStrategy,
    pub decoys: DecoyPolicy,
    pub issuer_type: SdJwtIssuerType,
}

impl Default for SdJwtIssuancePolicy {
    fn default() -> Self {
        SdJwtIssuancePolicy {
            disclosure_strategy: SdJwtDisclosureStrategy::TopLevel,
            decoys: DecoyPolicy::none(),
            issuer_type: SdJwtIssuerType::DigitalCredentialSdJwt,
        }
    }
}

pub struct SdJwtIssuanceInput<'a> {
    pub claims: Value,
    pub issuer_jwk: &'a Jwk,
    pub issuer_private_key: &'a [u8],
    pub policy: SdJwtIssuancePolicy,
}

impl fmt::Debug for SdJwtIssuanceInput<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SdJwtIssuanceInput([REDACTED])")
    }
}

#[derive(PartialEq, Eq)]
pub struct DisclosureRecord {
    pub path: String,
    pub encoded: String,
    pub digest: String,
}

impl fmt::Debug for DisclosureRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DisclosureRecord([REDACTED])")
    }
}

impl Zeroize for DisclosureRecord {
    fn zeroize(&mut self) {
        self.path.zeroize();
        self.encoded.zeroize();
        self.digest.zeroize();
    }
}

impl Drop for DisclosureRecord {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for DisclosureRecord {}

#[derive(PartialEq)]
pub struct IssuedSdJwt {
    pub issuer_payload: Value,
    pub issuer_signed_jwt: String,
    pub disclosures: Vec<String>,
    pub records: Vec<DisclosureRecord>,
    pub compact: String,
}

impl fmt::Debug for IssuedSdJwt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("IssuedSdJwt([REDACTED])")
    }
}

impl Zeroize for IssuedSdJwt {
    fn zeroize(&mut self) {
        zeroize_json_value(&mut self.issuer_payload);
        self.issuer_signed_jwt.zeroize();
        zeroize_strings(&mut self.disclosures);
        for record in &mut self.records {
            record.zeroize();
        }
        self.records.clear();
        self.compact.zeroize();
    }
}

impl Drop for IssuedSdJwt {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for IssuedSdJwt {}

pub fn issue_sd_jwt(
    input: SdJwtIssuanceInput<'_>,
    salt_source: &mut impl SdJwtSaltSource,
) -> Result<IssuedSdJwt, SdJwtEnvelopeError> {
    if !input.claims.is_object() {
        return Err(SdJwtEnvelopeError::InvalidIssuanceInput);
    }

    validate_disclosure_strategy(&input.policy.disclosure_strategy)?;
    let mut records = Vec::new();
    let issuer_payload = transform_value(
        &input.claims,
        "$",
        true,
        &input.policy,
        salt_source,
        &mut records,
    )?;
    let issuer_signed_jwt = encode_signed_jwt_with_header_options(
        &issuer_payload,
        input.issuer_jwk,
        input.issuer_private_key,
        &JwtHeaderEncodeOptions::new(input.policy.issuer_type.header_value()),
    )?;
    let disclosures = records
        .iter()
        .map(|record| record.encoded.clone())
        .collect::<Vec<String>>();
    let compact = serialize_sd_jwt_compact(&issuer_signed_jwt, &disclosures)?;

    Ok(IssuedSdJwt {
        issuer_payload,
        issuer_signed_jwt,
        disclosures,
        records,
        compact,
    })
}

fn transform_value(
    value: &Value,
    path: &str,
    is_root: bool,
    policy: &SdJwtIssuancePolicy,
    salt_source: &mut impl SdJwtSaltSource,
    records: &mut Vec<DisclosureRecord>,
) -> Result<Value, SdJwtEnvelopeError> {
    match value {
        Value::Object(object) => {
            transform_object(object, path, is_root, policy, salt_source, records)
        }
        Value::Array(array) => transform_array(array, path, policy, salt_source, records),
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => Ok(value.clone()),
    }
}

fn transform_object(
    object: &Map<String, Value>,
    path: &str,
    is_root: bool,
    policy: &SdJwtIssuancePolicy,
    salt_source: &mut impl SdJwtSaltSource,
    records: &mut Vec<DisclosureRecord>,
) -> Result<Value, SdJwtEnvelopeError> {
    let mut output = Map::new();
    let mut sd_digests = Vec::new();

    for (key, value) in object {
        if key == SD_CLAIM_NAME || key == SD_ALG_CLAIM_NAME || key == ARRAY_DIGEST_CLAIM_NAME {
            return Err(SdJwtEnvelopeError::InvalidReservedClaimPlacement);
        }

        let child_path = object_child_path(path, key);
        if is_root && is_non_selectively_disclosable_claim(key) {
            // Registered SD-JWT VC claims stay verbatim in the issuer payload;
            // neither the claim nor any nested member becomes disclosable.
            output.insert(key.clone(), value.clone());
            continue;
        }
        let transformed_child =
            transform_value(value, &child_path, false, policy, salt_source, records)?;
        if should_disclose(&child_path, &policy.disclosure_strategy) {
            let salt = salt_source.next_salt()?;
            let disclosure =
                create_object_property_disclosure(&salt, key, transformed_child.clone())?;
            let digest = digest_disclosure(disclosure.encoded(), SdJwtHashAlgorithm::Sha256)?;
            sd_digests.push(digest.clone());
            records.push(DisclosureRecord {
                path: child_path,
                encoded: disclosure.encoded().to_owned(),
                digest,
            });
        } else {
            output.insert(key.clone(), transformed_child);
        }
    }

    add_object_decoys(policy, salt_source, &mut sd_digests)?;
    if !sd_digests.is_empty() {
        sd_digests.sort();
        output.insert(
            SD_CLAIM_NAME.to_owned(),
            Value::Array(sd_digests.into_iter().map(Value::String).collect()),
        );
        if is_root {
            output.insert(
                SD_ALG_CLAIM_NAME.to_owned(),
                Value::String(SdJwtHashAlgorithm::Sha256.name().to_owned()),
            );
        }
    }

    Ok(Value::Object(output))
}

fn transform_array(
    array: &[Value],
    path: &str,
    policy: &SdJwtIssuancePolicy,
    salt_source: &mut impl SdJwtSaltSource,
    records: &mut Vec<DisclosureRecord>,
) -> Result<Value, SdJwtEnvelopeError> {
    let capacity = array
        .len()
        .checked_add(usize::from(policy.decoys.array_decoys))
        .ok_or(SdJwtEnvelopeError::InvalidIssuanceInput)?;
    let mut output = Vec::with_capacity(capacity);

    for (index, value) in array.iter().enumerate() {
        let child_path = array_child_path(path, index);
        let transformed_child =
            transform_value(value, &child_path, false, policy, salt_source, records)?;
        if should_disclose(&child_path, &policy.disclosure_strategy) {
            let salt = salt_source.next_salt()?;
            let disclosure = create_array_element_disclosure(&salt, transformed_child)?;
            let digest = digest_disclosure(disclosure.encoded(), SdJwtHashAlgorithm::Sha256)?;
            output.push(array_placeholder(&digest));
            records.push(DisclosureRecord {
                path: child_path,
                encoded: disclosure.encoded().to_owned(),
                digest,
            });
        } else {
            output.push(transformed_child);
        }
    }

    add_array_decoys(policy, salt_source, &mut output)?;
    Ok(Value::Array(output))
}

fn add_object_decoys(
    policy: &SdJwtIssuancePolicy,
    salt_source: &mut impl SdJwtSaltSource,
    sd_digests: &mut Vec<String>,
) -> Result<(), SdJwtEnvelopeError> {
    for _ in 0..policy.decoys.object_decoys {
        sd_digests.push(salt_source.next_decoy_digest()?);
    }

    Ok(())
}

fn add_array_decoys(
    policy: &SdJwtIssuancePolicy,
    salt_source: &mut impl SdJwtSaltSource,
    output: &mut Vec<Value>,
) -> Result<(), SdJwtEnvelopeError> {
    for _ in 0..policy.decoys.array_decoys {
        let digest = salt_source.next_decoy_digest()?;
        // RFC 9901 §4.2.5: decoys appended at a fixed position would be
        // trivially distinguishable from real element placeholders.
        let position = random_insert_position(salt_source, output.len())?;
        output.insert(position, array_placeholder(&digest));
    }

    Ok(())
}

/// Draw an insertion index in `0..=len` from fresh, unpublished salt-source
/// entropy so decoy placement is independent of any published digest.
fn random_insert_position(
    salt_source: &mut impl SdJwtSaltSource,
    len: usize,
) -> Result<usize, SdJwtEnvelopeError> {
    const POSITION_ENTROPY_BYTES: usize = 8;
    let entropy = salt_source.next_decoy_digest()?;
    let decoded = Zeroizing::new(
        base64url_to_bytes(&entropy).map_err(|_| SdJwtEnvelopeError::InvalidIssuanceInput)?,
    );
    let sample_bytes = decoded
        .len()
        .checked_sub(POSITION_ENTROPY_BYTES)
        .and_then(|start| decoded.get(start..))
        .and_then(|tail| <[u8; POSITION_ENTROPY_BYTES]>::try_from(tail).ok())
        .ok_or(SdJwtEnvelopeError::InvalidIssuanceInput)?;
    let bound = len
        .checked_add(1)
        .and_then(|value| u64::try_from(value).ok())
        .ok_or(SdJwtEnvelopeError::InvalidIssuanceInput)?;
    // The modulo bias is below bound / 2^64 for any bounded payload array.
    usize::try_from(u64::from_be_bytes(sample_bytes) % bound)
        .map_err(|_| SdJwtEnvelopeError::InvalidIssuanceInput)
}

/// Reject explicit JSON paths that would make a registered claim, or any
/// member nested under it, selectively disclosable.
fn validate_disclosure_strategy(
    strategy: &SdJwtDisclosureStrategy,
) -> Result<(), SdJwtEnvelopeError> {
    let SdJwtDisclosureStrategy::JsonPaths(paths) = strategy else {
        return Ok(());
    };
    for path in paths {
        let Some(rest) = path.strip_prefix("$.") else {
            continue;
        };
        let top_level_name = rest
            .find(['.', '['])
            .map_or(rest, |end| rest.get(..end).unwrap_or(rest));
        if is_non_selectively_disclosable_claim(top_level_name) {
            return Err(SdJwtEnvelopeError::NonSelectivelyDisclosableClaim);
        }
    }
    Ok(())
}

fn should_disclose(path: &str, strategy: &SdJwtDisclosureStrategy) -> bool {
    match strategy {
        SdJwtDisclosureStrategy::None => false,
        SdJwtDisclosureStrategy::TopLevel => {
            let Some(rest) = path.strip_prefix("$.") else {
                return false;
            };
            !rest.contains('.') && !rest.contains('[')
        }
        SdJwtDisclosureStrategy::AllLevels => true,
        SdJwtDisclosureStrategy::JsonPaths(paths) => paths.contains(path),
    }
}

fn object_child_path(parent: &str, key: &str) -> String {
    if parent == "$" {
        format!("$.{key}")
    } else {
        format!("{parent}.{key}")
    }
}

fn array_child_path(parent: &str, index: usize) -> String {
    format!("{parent}[{index}]")
}

fn array_placeholder(digest: &str) -> Value {
    let mut object = Map::new();
    object.insert(
        ARRAY_DIGEST_CLAIM_NAME.to_owned(),
        Value::String(digest.to_owned()),
    );
    Value::Object(object)
}
