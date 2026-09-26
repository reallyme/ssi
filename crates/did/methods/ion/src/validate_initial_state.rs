// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Authenticate the two content-addressed links in a long-form ION identifier.

use reallyme_codec::base64url::{base64url_to_bytes, bytes_to_base64url};
use reallyme_codec::jcs::{canonicalize_json_text, canonicalize_trusted_json_value};
use serde_json::Value;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::{DidIonError, DidIonErrorReason};

const SHA256_MULTIHASH_PREFIX: [u8; 2] = [0x12, 0x20];
const MULTIHASH_BYTES: usize = 34;
const ENCODED_MULTIHASH_BYTES: usize = 46;
const MAX_ENCODED_INITIAL_STATE_BYTES: usize = 22_000;
const MAX_DELTA_BYTES: usize = 1_000;

pub(crate) fn validate_suffix(suffix: &str) -> Result<(), DidIonError> {
    if suffix.is_empty() {
        return Err(DidIonError::new(DidIonErrorReason::EmptySuffix));
    }
    validate_multihash(suffix).map_err(|_| DidIonError::new(DidIonErrorReason::InvalidSuffix))
}

fn validate_multihash(encoded: &str) -> Result<(), DidIonError> {
    if encoded.len() != ENCODED_MULTIHASH_BYTES {
        return Err(invalid());
    }
    let bytes = base64url_to_bytes(encoded).map_err(|_| invalid())?;
    if bytes.len() != MULTIHASH_BYTES
        || !bytes.starts_with(&SHA256_MULTIHASH_PREFIX)
        || bytes_to_base64url(&bytes) != encoded
    {
        return Err(invalid());
    }
    Ok(())
}

pub(crate) fn validate_initial_state(suffix: &str, encoded: &str) -> Result<(), DidIonError> {
    if encoded.len() > MAX_ENCODED_INITIAL_STATE_BYTES {
        return Err(DidIonError::new(DidIonErrorReason::TooLarge));
    }
    let decoded = Zeroizing::new(base64url_to_bytes(encoded).map_err(|_| invalid())?);
    if bytes_to_base64url(&decoded) != encoded {
        return Err(invalid());
    }
    identity_core_primitives::validate_json::validate_json(&decoded).map_err(|_| invalid())?;
    let text = core::str::from_utf8(&decoded).map_err(|_| invalid())?;
    let canonical = Zeroizing::new(canonicalize_json_text(text).map_err(|_| invalid())?);
    if canonical.as_bytes() != decoded.as_slice() {
        return Err(invalid());
    }
    let state = OwnedJson(serde_json::from_slice(&decoded).map_err(|_| invalid())?);
    let object = state.0.as_object().ok_or_else(invalid)?;
    if object.len() != 2 {
        return Err(invalid());
    }
    let suffix_data = object.get("suffixData").ok_or_else(invalid)?;
    let suffix_object = suffix_data.as_object().ok_or_else(invalid)?;
    if suffix_object.len() != 2 {
        return Err(invalid());
    }
    let delta_hash = suffix_object
        .get("deltaHash")
        .and_then(Value::as_str)
        .ok_or_else(invalid)?;
    let recovery = suffix_object
        .get("recoveryCommitment")
        .and_then(Value::as_str)
        .ok_or_else(invalid)?;
    validate_multihash(delta_hash)?;
    validate_multihash(recovery)?;
    let canonical_suffix =
        Zeroizing::new(canonicalize_trusted_json_value(suffix_data).map_err(|_| invalid())?);
    if hash_encoded(canonical_suffix.as_bytes()) != suffix {
        return Err(DidIonError::new(DidIonErrorReason::SuffixMismatch));
    }
    let delta = object.get("delta").ok_or_else(invalid)?;
    let delta_object = delta.as_object().ok_or_else(invalid)?;
    if delta_object.len() != 2 || !delta_object.get("patches").is_some_and(Value::is_array) {
        return Err(invalid());
    }
    validate_multihash(
        delta_object
            .get("updateCommitment")
            .and_then(Value::as_str)
            .ok_or_else(invalid)?,
    )?;
    let canonical_delta =
        Zeroizing::new(canonicalize_trusted_json_value(delta).map_err(|_| invalid())?);
    if canonical_delta.len() > MAX_DELTA_BYTES {
        return Err(DidIonError::new(DidIonErrorReason::TooLarge));
    }
    if hash_encoded(canonical_delta.as_bytes()) != delta_hash {
        return Err(DidIonError::new(DidIonErrorReason::DeltaHashMismatch));
    }
    Ok(())
}

fn hash_encoded(bytes: &[u8]) -> String {
    let digest = reallyme_crypto::sha2::digest(bytes).into_bytes();
    let mut multihash = [0_u8; MULTIHASH_BYTES];
    multihash[..2].copy_from_slice(&SHA256_MULTIHASH_PREFIX);
    multihash[2..].copy_from_slice(&digest);
    bytes_to_base64url(&multihash)
}

fn invalid() -> DidIonError {
    DidIonError::new(DidIonErrorReason::InvalidInitialState)
}

// JSON may contain identity data even when a commitment fails. Scrub its owned
// strings and containers on both success and every early error return.
struct OwnedJson(Value);
impl Zeroize for OwnedJson {
    fn zeroize(&mut self) {
        clear_value(&mut self.0);
    }
}
impl Drop for OwnedJson {
    fn drop(&mut self) {
        self.zeroize();
    }
}
impl ZeroizeOnDrop for OwnedJson {}
fn clear_value(value: &mut Value) {
    match value {
        Value::String(text) => text.zeroize(),
        Value::Array(items) => items.iter_mut().for_each(clear_value),
        Value::Object(map) => {
            for (mut key, mut child) in core::mem::take(map) {
                key.zeroize();
                clear_value(&mut child);
            }
        }
        _ => {}
    }
    *value = Value::Null;
}
