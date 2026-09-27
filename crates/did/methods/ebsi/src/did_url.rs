// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! DID Core syntax checks used at EBSI document boundaries.

use crate::{DidEbsiError, DidEbsiErrorReason};

pub(crate) fn validate_base_did(value: &str) -> Result<(), DidEbsiError> {
    let remainder = value
        .strip_prefix("did:")
        .ok_or(DidEbsiError::new(DidEbsiErrorReason::InvalidDidUrl))?;
    let (method, identifier) = remainder
        .split_once(':')
        .ok_or(DidEbsiError::new(DidEbsiErrorReason::InvalidDidUrl))?;
    if method.is_empty()
        || !method
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        || identifier.is_empty()
        || identifier.ends_with(':')
    {
        return Err(DidEbsiError::new(DidEbsiErrorReason::InvalidDidUrl));
    }
    validate_component(identifier, |byte| {
        byte == b':' || is_identifier_character(byte)
    })
}

pub(crate) fn validate_absolute_did_url(value: &str) -> Result<(), DidEbsiError> {
    let suffix_index = value.find(['/', '?', '#']).unwrap_or(value.len());
    validate_base_did(&value[..suffix_index])?;
    validate_suffix(&value[suffix_index..])
}

fn validate_suffix(value: &str) -> Result<(), DidEbsiError> {
    if value.matches('#').count() > 1 {
        return Err(DidEbsiError::new(DidEbsiErrorReason::InvalidDidUrl));
    }
    let (before_fragment, fragment) = value
        .split_once('#')
        .map_or((value, None), |(prefix, suffix)| (prefix, Some(suffix)));
    let (path, query) = before_fragment
        .split_once('?')
        .map_or((before_fragment, None), |(prefix, suffix)| {
            (prefix, Some(suffix))
        });
    if !path.is_empty() {
        if !path.starts_with('/') {
            return Err(DidEbsiError::new(DidEbsiErrorReason::InvalidDidUrl));
        }
        validate_component(path, |byte| byte == b'/' || is_path_character(byte))?;
    }
    if let Some(query) = query {
        validate_component(query, is_query_or_fragment_character)?;
    }
    if let Some(fragment) = fragment {
        validate_component(fragment, is_query_or_fragment_character)?;
    }
    Ok(())
}

fn validate_component(value: &str, allows_raw: impl Fn(u8) -> bool) -> Result<(), DidEbsiError> {
    let bytes = value.as_bytes();
    let mut index = 0usize;
    while index < bytes.len() {
        let byte = *bytes
            .get(index)
            .ok_or(DidEbsiError::new(DidEbsiErrorReason::InvalidDidUrl))?;
        if byte == b'%' {
            let first = *bytes
                .get(
                    index
                        .checked_add(1)
                        .ok_or(DidEbsiError::new(DidEbsiErrorReason::InvalidDidUrl))?,
                )
                .ok_or(DidEbsiError::new(DidEbsiErrorReason::InvalidDidUrl))?;
            let second = *bytes
                .get(
                    index
                        .checked_add(2)
                        .ok_or(DidEbsiError::new(DidEbsiErrorReason::InvalidDidUrl))?,
                )
                .ok_or(DidEbsiError::new(DidEbsiErrorReason::InvalidDidUrl))?;
            if !first.is_ascii_hexdigit() || !second.is_ascii_hexdigit() {
                return Err(DidEbsiError::new(DidEbsiErrorReason::InvalidDidUrl));
            }
            let decoded = decode_hex_pair(first, second)
                .ok_or(DidEbsiError::new(DidEbsiErrorReason::InvalidDidUrl))?;
            if is_unreserved(decoded) || first.is_ascii_lowercase() || second.is_ascii_lowercase() {
                return Err(DidEbsiError::new(DidEbsiErrorReason::InvalidDidUrl));
            }
            index = index
                .checked_add(3)
                .ok_or(DidEbsiError::new(DidEbsiErrorReason::InvalidDidUrl))?;
        } else {
            if !allows_raw(byte) {
                return Err(DidEbsiError::new(DidEbsiErrorReason::InvalidDidUrl));
            }
            index = index
                .checked_add(1)
                .ok_or(DidEbsiError::new(DidEbsiErrorReason::InvalidDidUrl))?;
        }
    }
    Ok(())
}

fn is_identifier_character(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_')
}

fn is_unreserved(byte: u8) -> bool {
    is_identifier_character(byte) || byte == b'~'
}

fn is_path_character(byte: u8) -> bool {
    is_identifier_character(byte)
        || matches!(
            byte,
            b'~' | b'!'
                | b'$'
                | b'&'
                | b'\''
                | b'('
                | b')'
                | b'*'
                | b'+'
                | b','
                | b';'
                | b'='
                | b':'
                | b'@'
        )
}

fn is_query_or_fragment_character(byte: u8) -> bool {
    is_path_character(byte) || matches!(byte, b'/' | b'?')
}

fn decode_hex_pair(first: u8, second: u8) -> Option<u8> {
    let high = hex_nibble(first)?;
    let low = hex_nibble(second)?;
    Some((high << 4) | low)
}

fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => value.checked_sub(b'0'),
        b'a'..=b'f' => value.checked_sub(b'a')?.checked_add(10),
        b'A'..=b'F' => value.checked_sub(b'A')?.checked_add(10),
        _ => None,
    }
}
