// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Offline DID and DID URL parsing for SDK-facing DID taxonomy commands.

use reallyme_did_method_ebsi::parse_did_ebsi;
use reallyme_did_method_me::parse_did_me;
use reallyme_did_method_web::parse_did_web;

use crate::error::DidApiError;

const DID_PREFIX: &str = "did:";
const DID_ME_METHOD: &str = "me";
const DID_EBSI_METHOD: &str = "ebsi";
const DID_WEB_METHOD: &str = "web";

/// Typed, non-PII failures produced by offline DID and DID URL parsing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DidParseError {
    /// The input does not have a valid DID URL structure.
    #[error("invalid DID URL")]
    InvalidDidUrl,

    /// The input has a valid DID shape but fails did:me method validation.
    #[error("invalid DID")]
    InvalidDid,
}

impl From<DidParseError> for DidApiError {
    fn from(error: DidParseError) -> Self {
        match error {
            DidParseError::InvalidDidUrl => Self::InvalidDidUrl,
            DidParseError::InvalidDid => Self::InvalidDid,
        }
    }
}

/// Request for offline DID parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DidParseRequest {
    /// DID or DID URL to parse.
    pub did_url: String,
}

/// Parsed DID and DID URL components.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DidParseResult {
    /// DID without path, query, or fragment components.
    pub did: String,

    /// DID method name.
    pub method: String,

    /// Method-specific identifier.
    pub method_specific_id: String,

    /// DID URL path, if present.
    pub path: Option<String>,

    /// DID URL query, if present.
    pub query: Option<String>,

    /// DID URL fragment without the leading `#`, if present.
    pub fragment: Option<String>,

    /// Whether the input contains DID URL components beyond the base DID.
    pub is_did_url: bool,

    /// Whether this identity-core package has method-specific validation for the method.
    pub method_supported: bool,
}

/// Parse a DID or DID URL without performing network access.
pub fn parse_did(request: DidParseRequest) -> Result<DidParseResult, DidApiError> {
    parse_did_value(&request.did_url).map_err(DidApiError::from)
}

/// Parse a borrowed DID or DID URL for allocation-conscious callers.
///
/// Borrowing avoids an additional immutable copy of the identifying input at
/// public parsing boundaries.
pub fn parse_did_value(did_url: &str) -> Result<DidParseResult, DidParseError> {
    if !did_url.starts_with(DID_PREFIX) {
        return Err(DidParseError::InvalidDidUrl);
    }

    let (before_fragment, fragment) = split_fragment(did_url)?;
    let (before_query, query) = split_query(before_fragment)?;
    let base = split_base_did(before_query)?;

    if base.method == DID_ME_METHOD {
        parse_did_me(base.did).map_err(|_| DidParseError::InvalidDid)?;
    } else if base.method == DID_EBSI_METHOD {
        parse_did_ebsi(base.did).map_err(|_| DidParseError::InvalidDid)?;
    } else if base.method == DID_WEB_METHOD {
        parse_did_web(base.did).map_err(|_| DidParseError::InvalidDid)?;
    }

    let is_did_url = base.path.is_some() || query.is_some() || fragment.is_some();

    Ok(DidParseResult {
        did: base.did.to_owned(),
        method: base.method.to_owned(),
        method_specific_id: base.method_specific_id.to_owned(),
        path: base.path.map(str::to_owned),
        query: query.map(str::to_owned),
        fragment: fragment.map(str::to_owned),
        is_did_url,
        method_supported: matches!(
            base.method,
            DID_ME_METHOD | DID_WEB_METHOD | DID_EBSI_METHOD
        ),
    })
}

pub(crate) fn parse_did_url(did_url: &str) -> Result<DidParseResult, DidApiError> {
    parse_did_value(did_url).map_err(DidApiError::from)
}

struct BaseDidParts<'a> {
    did: &'a str,
    method: &'a str,
    method_specific_id: &'a str,
    path: Option<&'a str>,
}

fn split_fragment(did_url: &str) -> Result<(&str, Option<&str>), DidParseError> {
    let Some((before_fragment, fragment)) = did_url.split_once('#') else {
        return Ok((did_url, None));
    };

    if fragment.is_empty() || fragment.contains('#') {
        return Err(DidParseError::InvalidDidUrl);
    }

    Ok((before_fragment, Some(fragment)))
}

fn split_query(before_fragment: &str) -> Result<(&str, Option<&str>), DidParseError> {
    let Some((before_query, query)) = before_fragment.split_once('?') else {
        return Ok((before_fragment, None));
    };

    if query.is_empty() {
        return Err(DidParseError::InvalidDidUrl);
    }

    Ok((before_query, Some(query)))
}

fn split_base_did(did_part: &str) -> Result<BaseDidParts<'_>, DidParseError> {
    let without_prefix = did_part
        .strip_prefix(DID_PREFIX)
        .ok_or(DidParseError::InvalidDidUrl)?;
    let method_end = without_prefix
        .find(':')
        .ok_or(DidParseError::InvalidDidUrl)?;
    let method = &without_prefix[..method_end];

    if method.is_empty()
        || !method
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
    {
        return Err(DidParseError::InvalidDidUrl);
    }

    let method_specific_and_path = &without_prefix[method_end + 1..];
    if method_specific_and_path.is_empty() {
        return Err(DidParseError::InvalidDidUrl);
    }

    let path_start = method_specific_and_path.find('/');
    let method_specific_id = match path_start {
        Some(index) => &method_specific_and_path[..index],
        None => method_specific_and_path,
    };

    if method_specific_id.is_empty() {
        return Err(DidParseError::InvalidDidUrl);
    }

    let path = path_start.map(|index| &method_specific_and_path[index..]);
    let method_specific_offset = DID_PREFIX
        .len()
        .checked_add(method_end)
        .and_then(|offset| offset.checked_add(1))
        .ok_or(DidParseError::InvalidDidUrl)?;
    let base_end = method_specific_offset
        .checked_add(method_specific_id.len())
        .ok_or(DidParseError::InvalidDidUrl)?;

    Ok(BaseDidParts {
        did: &did_part[..base_end],
        method,
        method_specific_id,
        path,
    })
}
