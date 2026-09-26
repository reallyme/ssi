// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Strict RFC 8392 CWT claims-set decoding for the `rc-wrp+cwt` payload.
//!
//! The COSE_Sign1 payload of a CWT is a CBOR map, not JSON. Registered claims
//! use the integer keys assigned by RFC 8392 section 3.1 and the IANA "CBOR
//! Web Token (CWT) Claims" registry, and are projected onto the same claim
//! names used by the JWT representation so both encodings share one closed
//! TS 119 475 claim model. Claims without a registered integer key use CBOR
//! text-string keys, exactly as in the JWT representation.

use std::collections::BTreeMap;

use super::cbor::Decoder;
use crate::json::{
    StrictValue, MAX_JSON_BYTES, MAX_JSON_DEPTH, MAX_JSON_ITEMS, MAX_JSON_MEMBERS,
    MAX_JSON_STRING_BYTES,
};
use crate::{RegistrationError, RegistrationErrorReason};

/// Largest accepted CWT claims-set encoding, shared with the JWT payload bound.
const MAX_CWT_CLAIMS_BYTES: usize = MAX_JSON_BYTES;
/// Deepest accepted nesting of CBOR arrays and maps, including the claims map.
const MAX_CWT_DEPTH: usize = MAX_JSON_DEPTH;
/// Largest accepted CBOR array.
const MAX_CWT_ARRAY_ITEMS: usize = MAX_JSON_ITEMS;
/// Largest accepted CBOR map, including the claims map.
const MAX_CWT_MAP_ENTRIES: usize = MAX_JSON_MEMBERS;
/// Largest accepted CBOR text string, in bytes.
const MAX_CWT_TEXT_BYTES: usize = MAX_JSON_STRING_BYTES;

const CBOR_MAJOR_UNSIGNED: u8 = 0;
const CBOR_MAJOR_NEGATIVE: u8 = 1;
const CBOR_MAJOR_TEXT: u8 = 3;
const CBOR_MAJOR_ARRAY: u8 = 4;
const CBOR_MAJOR_MAP: u8 = 5;
const CBOR_MAJOR_SIMPLE: u8 = 7;
const CBOR_SIMPLE_FALSE: u64 = 20;
const CBOR_SIMPLE_TRUE: u64 = 21;
const CBOR_SIMPLE_NULL: u64 = 22;

/// Registered CWT claim keys and the equivalent JWT claim names.
///
/// Keys 1 through 7 are assigned by RFC 8392 section 3.1. Key 65535 is the
/// Token Status List `status` claim registered in the IANA CWT Claims
/// registry, carried by TS 119 475 WRPRCs for revocation status.
const REGISTERED_CLAIMS: [(u64, &str); 8] = [
    (1, "iss"),
    (2, "sub"),
    (3, "aud"),
    (4, "exp"),
    (5, "nbf"),
    (6, "iat"),
    (7, "cti"),
    (65_535, "status"),
];

/// Decodes one bounded CWT claims set into the shared closed claim model.
pub(super) fn decode_cwt_claims(payload: &[u8]) -> Result<StrictValue, RegistrationError> {
    if payload.is_empty() {
        return Err(invalid(RegistrationErrorReason::EmptyInput));
    }
    if payload.len() > MAX_CWT_CLAIMS_BYTES {
        return Err(invalid(RegistrationErrorReason::InputTooLarge));
    }
    let mut decoder = Decoder::new(payload);
    if decoder.peek_major_type()? != Some(CBOR_MAJOR_MAP) {
        return Err(invalid(RegistrationErrorReason::InvalidField));
    }
    let count = decoder.read_map_length()?;
    if count > MAX_CWT_MAP_ENTRIES {
        return Err(invalid(RegistrationErrorReason::ResourceLimitExceeded));
    }
    let mut claims = BTreeMap::new();
    for _ in 0..count {
        let name = read_claim_key(&mut decoder)?;
        if claims.contains_key(&name) {
            return Err(invalid(RegistrationErrorReason::DuplicateJsonMember));
        }
        let value = decode_item(&mut decoder, 1)?;
        claims.insert(name, value);
    }
    if !decoder.is_finished() {
        return Err(invalid(RegistrationErrorReason::InvalidField));
    }
    Ok(StrictValue::Object(claims))
}

fn read_claim_key(decoder: &mut Decoder<'_>) -> Result<String, RegistrationError> {
    match decoder.peek_major_type()? {
        Some(CBOR_MAJOR_UNSIGNED) => {
            let key = decoder.read_unsigned()?;
            REGISTERED_CLAIMS
                .iter()
                .find(|(registered, _name)| *registered == key)
                .map(|(_registered, name)| (*name).to_owned())
                .ok_or_else(|| invalid(RegistrationErrorReason::UnknownField))
        }
        Some(CBOR_MAJOR_NEGATIVE) => Err(invalid(RegistrationErrorReason::UnknownField)),
        Some(CBOR_MAJOR_TEXT) => {
            let name = read_bounded_text(decoder)?;
            // RFC 8392 section 3.1 assigns these claims integer keys. A text
            // key with the same name would be a distinct, ambiguous claim.
            if REGISTERED_CLAIMS
                .iter()
                .any(|(_registered, registered_name)| *registered_name == name)
            {
                return Err(invalid(RegistrationErrorReason::InvalidField));
            }
            Ok(name)
        }
        _ => Err(invalid(RegistrationErrorReason::InvalidField)),
    }
}

fn decode_item(decoder: &mut Decoder<'_>, depth: usize) -> Result<StrictValue, RegistrationError> {
    match decoder.peek_major_type()? {
        Some(CBOR_MAJOR_UNSIGNED) => Ok(StrictValue::Number(decoder.read_unsigned()?.into())),
        Some(CBOR_MAJOR_NEGATIVE) => Ok(StrictValue::Number(decoder.read_integer()?.into())),
        Some(CBOR_MAJOR_TEXT) => read_bounded_text(decoder).map(StrictValue::String),
        Some(CBOR_MAJOR_ARRAY) => decode_array(decoder, next_depth(depth)?),
        Some(CBOR_MAJOR_MAP) => decode_map(decoder, next_depth(depth)?),
        Some(CBOR_MAJOR_SIMPLE) => match decoder.read_head()? {
            (_major, CBOR_SIMPLE_FALSE) => Ok(StrictValue::Bool(false)),
            (_major, CBOR_SIMPLE_TRUE) => Ok(StrictValue::Bool(true)),
            (_major, CBOR_SIMPLE_NULL) => Ok(StrictValue::Null),
            // Floating-point, undefined, and unassigned simple values have no
            // counterpart in the closed WRPRC claim model.
            _ => Err(invalid(RegistrationErrorReason::InvalidField)),
        },
        // Byte strings, tags, and truncated input have no counterpart in the
        // JWT claim model.
        _ => Err(invalid(RegistrationErrorReason::InvalidField)),
    }
}

fn decode_array(decoder: &mut Decoder<'_>, depth: usize) -> Result<StrictValue, RegistrationError> {
    let count = decoder.read_array_length()?;
    if count > MAX_CWT_ARRAY_ITEMS {
        return Err(invalid(RegistrationErrorReason::ResourceLimitExceeded));
    }
    let mut values = Vec::new();
    values
        .try_reserve_exact(count)
        .map_err(|_error| invalid(RegistrationErrorReason::CapacityUnavailable))?;
    for _ in 0..count {
        values.push(decode_item(decoder, depth)?);
    }
    Ok(StrictValue::Array(values))
}

fn decode_map(decoder: &mut Decoder<'_>, depth: usize) -> Result<StrictValue, RegistrationError> {
    let count = decoder.read_map_length()?;
    if count > MAX_CWT_MAP_ENTRIES {
        return Err(invalid(RegistrationErrorReason::ResourceLimitExceeded));
    }
    let mut values = BTreeMap::new();
    for _ in 0..count {
        if decoder.peek_major_type()? != Some(CBOR_MAJOR_TEXT) {
            return Err(invalid(RegistrationErrorReason::InvalidField));
        }
        let name = read_bounded_text(decoder)?;
        if values.contains_key(&name) {
            return Err(invalid(RegistrationErrorReason::DuplicateJsonMember));
        }
        let value = decode_item(decoder, depth)?;
        values.insert(name, value);
    }
    Ok(StrictValue::Object(values))
}

fn read_bounded_text(decoder: &mut Decoder<'_>) -> Result<String, RegistrationError> {
    let value = decoder.read_text_string()?;
    if value.len() > MAX_CWT_TEXT_BYTES || value.bytes().any(|byte| byte == 0) {
        return Err(invalid(RegistrationErrorReason::ResourceLimitExceeded));
    }
    Ok(value.to_owned())
}

fn next_depth(depth: usize) -> Result<usize, RegistrationError> {
    let next = depth
        .checked_add(1)
        .ok_or_else(|| invalid(RegistrationErrorReason::ResourceLimitExceeded))?;
    if next > MAX_CWT_DEPTH {
        return Err(invalid(RegistrationErrorReason::ResourceLimitExceeded));
    }
    Ok(next)
}

const fn invalid(reason: RegistrationErrorReason) -> RegistrationError {
    RegistrationError::from_reason(reason)
}
