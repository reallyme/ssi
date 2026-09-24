// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Strict absolute DID and DID URL validation shared by document semantics.

use crate::error::{DidWebError, DidWebErrorReason};
use crate::method::parse_did_web;

pub(crate) fn validate_absolute_did_url(
    value: &str,
    require_fragment: bool,
) -> Result<(), DidWebError> {
    let suffix_index = value.find(['/', '?', '#']).unwrap_or(value.len());
    let base = &value[..suffix_index];
    validate_base_did(base, DidWebErrorReason::InvalidDidUrl)?;
    let suffix = &value[suffix_index..];
    if require_fragment && (!suffix.contains('#') || suffix.ends_with('#')) {
        return Err(DidWebError::new(DidWebErrorReason::InvalidDidUrl));
    }
    validate_url_suffix(suffix)
}

pub(crate) fn validate_base_did(value: &str, reason: DidWebErrorReason) -> Result<(), DidWebError> {
    let remainder = value.strip_prefix("did:").ok_or(DidWebError::new(reason))?;
    let (method, identifier) = remainder.split_once(':').ok_or(DidWebError::new(reason))?;
    if method.is_empty()
        || !method
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        || identifier.is_empty()
    {
        return Err(DidWebError::new(reason));
    }
    if method == "web" {
        parse_did_web(value).map_err(|_| DidWebError::new(reason))?;
    } else {
        for component in identifier.split(':') {
            if component.is_empty() {
                return Err(DidWebError::new(reason));
            }
            validate_uri_component(component, is_did_identifier_character, reason)?;
        }
    }
    Ok(())
}

fn validate_url_suffix(value: &str) -> Result<(), DidWebError> {
    if value.is_empty() {
        return Ok(());
    }
    if value.matches('#').count() > 1 {
        return Err(DidWebError::new(DidWebErrorReason::InvalidDidUrl));
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
            return Err(DidWebError::new(DidWebErrorReason::InvalidDidUrl));
        }
        for component in path.split('/').skip(1) {
            validate_uri_component(
                component,
                is_path_character,
                DidWebErrorReason::InvalidDidUrl,
            )?;
        }
    }
    if let Some(query) = query {
        validate_nonempty_url_component(query)?;
    }
    if let Some(fragment) = fragment {
        validate_nonempty_url_component(fragment)?;
    }
    Ok(())
}

fn validate_nonempty_url_component(value: &str) -> Result<(), DidWebError> {
    if value.is_empty() {
        return Err(DidWebError::new(DidWebErrorReason::InvalidDidUrl));
    }
    validate_uri_component(
        value,
        is_query_or_fragment_character,
        DidWebErrorReason::InvalidDidUrl,
    )
}

fn validate_uri_component(
    value: &str,
    allows_raw: fn(u8) -> bool,
    reason: DidWebErrorReason,
) -> Result<(), DidWebError> {
    let bytes = value.as_bytes();
    let mut index = 0usize;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let first = *bytes
                .get(index.checked_add(1).ok_or(DidWebError::new(reason))?)
                .ok_or(DidWebError::new(reason))?;
            let second = *bytes
                .get(index.checked_add(2).ok_or(DidWebError::new(reason))?)
                .ok_or(DidWebError::new(reason))?;
            if !first.is_ascii_hexdigit()
                || !second.is_ascii_hexdigit()
                || first.is_ascii_lowercase()
                || second.is_ascii_lowercase()
            {
                return Err(DidWebError::new(reason));
            }
            let decoded = decode_hex_pair(first, second).ok_or(DidWebError::new(reason))?;
            if is_unreserved(decoded) {
                return Err(DidWebError::new(reason));
            }
            index = index.checked_add(3).ok_or(DidWebError::new(reason))?;
        } else {
            if !allows_raw(bytes[index]) {
                return Err(DidWebError::new(reason));
            }
            index = index.checked_add(1).ok_or(DidWebError::new(reason))?;
        }
    }
    Ok(())
}

fn is_did_identifier_character(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_')
}

fn is_unreserved(byte: u8) -> bool {
    is_did_identifier_character(byte) || byte == b'~'
}

fn is_path_character(byte: u8) -> bool {
    is_unreserved(byte)
        || matches!(
            byte,
            b'!' | b'$'
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
        b'0'..=b'9' => Some(value - b'0'),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}
