// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::{ClaimsError, ClaimsInvalidReason};

const CLAIM_PATH_ROOT: &str = "/claims";
const CLAIM_PATH_PREFIX: &str = "/claims/";
// Numeric JSON object member names occur in external credential profiles such
// as ARF PID `age_equal_or_over`. They must not be parsed as array selectors,
// so canonical claim paths reserve `~2` for numeric field segments.
const NUMERIC_FIELD_ESCAPE: &str = "~2";

/// Maximum UTF-8 bytes in a canonical claim path.
pub const MAX_CLAIM_PATH_BYTES: usize = 1024;

/// Maximum nested path segments below `/claims`.
pub const MAX_CLAIM_PATH_DEPTH: usize = 32;

/// Maximum UTF-8 bytes in one decoded object field segment.
pub const MAX_CLAIM_PATH_SEGMENT_BYTES: usize = 128;

/// Parsed canonical path below the credential claim root.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClaimPath {
    segments: Vec<ClaimPathSegment>,
}

/// One canonical path segment below `/claims`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ClaimPathSegment {
    /// Object member selected by escaped JSON Pointer token.
    Field(String),

    /// Array element selected by a decimal index segment.
    ArrayIndex(u32),
}

impl ClaimPath {
    /// Parse a canonical claim path.
    pub fn parse(path: &str) -> Result<Self, ClaimsError> {
        parse_claim_path(path)
    }

    /// Return the canonical claim identifier without the `/claims/` prefix.
    pub fn claim_id(&self) -> Option<String> {
        if self.segments.is_empty() {
            return None;
        }
        let mut out = String::new();
        for segment in &self.segments {
            if !out.is_empty() {
                out.push('/');
            }
            let encoded = segment.as_canonical_segment();
            out.push_str(encoded.as_str());
        }
        Some(out)
    }

    /// Return a borrowed view of path segments.
    pub fn segments(&self) -> &[ClaimPathSegment] {
        &self.segments
    }

    /// Return true when this path is a strict ancestor of another path.
    pub fn is_strict_ancestor_of(&self, other: &Self) -> bool {
        self.segments.len() < other.segments.len()
            && other.segments.starts_with(self.segments.as_slice())
    }

    /// Return the canonical claim identifiers of every strict, non-root ancestor.
    ///
    /// Canonical segment rendering is injective, so identifier equality is
    /// equivalent to segment-wise equality used by [`Self::is_strict_ancestor_of`].
    pub(crate) fn strict_ancestor_claim_ids(&self) -> Vec<String> {
        let ancestor_count = self.segments.len().saturating_sub(1);
        let mut out = Vec::with_capacity(ancestor_count);
        let mut current = String::new();
        for segment in self.segments.iter().take(ancestor_count) {
            if !current.is_empty() {
                current.push('/');
            }
            current.push_str(segment.as_canonical_segment().as_str());
            out.push(current.clone());
        }
        out
    }
}

impl ClaimPathSegment {
    fn as_canonical_segment(&self) -> String {
        match self {
            Self::Field(field) => escape_field_segment(field),
            Self::ArrayIndex(index) => index.to_string(),
        }
    }
}

/// Return the canonical disclosure path for a claim identifier.
pub fn claim_path(claim_id: &str) -> Option<String> {
    if !is_valid_claim_id(claim_id) {
        return None;
    }
    let capacity = CLAIM_PATH_PREFIX.len().checked_add(claim_id.len())?;
    let mut out = String::with_capacity(capacity);
    out.push_str(CLAIM_PATH_PREFIX);
    out.push_str(claim_id);
    Some(out)
}

/// Extract a claim identifier from a canonical claim path.
pub fn claim_id_from_path(path: &str) -> Option<&str> {
    let claim_id = path.strip_prefix(CLAIM_PATH_PREFIX)?;
    if parse_claim_path(path).is_ok() {
        Some(claim_id)
    } else {
        None
    }
}

/// Return whether a claim identifier is canonical for this registry layer.
pub fn is_valid_claim_id(claim_id: &str) -> bool {
    if claim_id.trim().is_empty() {
        return false;
    }
    let Some(path_len) = CLAIM_PATH_PREFIX.len().checked_add(claim_id.len()) else {
        return false;
    };
    let mut path = String::with_capacity(path_len);
    path.push_str(CLAIM_PATH_PREFIX);
    path.push_str(claim_id);
    parse_claim_path(path.as_str()).is_ok()
}

/// Parse a canonical claim path.
pub fn parse_claim_path(path: &str) -> Result<ClaimPath, ClaimsError> {
    if path.len() > MAX_CLAIM_PATH_BYTES {
        return Err(ClaimsError::InvalidInput(
            ClaimsInvalidReason::ClaimPathTooLong,
        ));
    }
    if path == CLAIM_PATH_ROOT {
        return Ok(ClaimPath {
            segments: Vec::new(),
        });
    }
    let remainder = path
        .strip_prefix(CLAIM_PATH_PREFIX)
        .ok_or(ClaimsError::InvalidInput(
            ClaimsInvalidReason::InvalidClaimPath,
        ))?;
    if remainder.is_empty() || remainder.ends_with('/') {
        return Err(ClaimsError::InvalidInput(
            ClaimsInvalidReason::InvalidClaimPath,
        ));
    }

    let raw_segments: Vec<&str> = remainder.split('/').collect();
    if raw_segments.len() > MAX_CLAIM_PATH_DEPTH {
        return Err(ClaimsError::InvalidInput(
            ClaimsInvalidReason::ClaimPathTooDeep,
        ));
    }

    let mut segments = Vec::with_capacity(raw_segments.len());
    for raw in raw_segments {
        if raw.is_empty() {
            return Err(ClaimsError::InvalidInput(
                ClaimsInvalidReason::InvalidClaimPath,
            ));
        }
        segments.push(parse_segment(raw)?);
    }
    if matches!(segments.first(), Some(ClaimPathSegment::ArrayIndex(_))) {
        return Err(ClaimsError::InvalidInput(
            ClaimsInvalidReason::InvalidClaimPathSegment,
        ));
    }

    Ok(ClaimPath { segments })
}

fn parse_segment(raw: &str) -> Result<ClaimPathSegment, ClaimsError> {
    reject_wildcard(raw)?;
    if is_decimal_index(raw) {
        let index = parse_array_index(raw)?;
        return Ok(ClaimPathSegment::ArrayIndex(index));
    }
    let (field, numeric_field_escape) = decode_field_segment(raw)?;
    validate_field_segment(field.as_str(), numeric_field_escape)?;
    Ok(ClaimPathSegment::Field(field))
}

fn reject_wildcard(raw: &str) -> Result<(), ClaimsError> {
    if raw == "*" {
        return Err(ClaimsError::InvalidInput(
            ClaimsInvalidReason::WildcardClaimPathNotAllowed,
        ));
    }
    Ok(())
}

fn parse_array_index(raw: &str) -> Result<u32, ClaimsError> {
    if raw.len() > 1 && raw.starts_with('0') {
        return Err(ClaimsError::InvalidInput(
            ClaimsInvalidReason::InvalidClaimPathSegment,
        ));
    }
    raw.parse::<u32>()
        .map_err(|_| ClaimsError::InvalidInput(ClaimsInvalidReason::InvalidClaimPathSegment))
}

fn is_decimal_index(raw: &str) -> bool {
    raw.bytes().all(|byte| byte.is_ascii_digit())
}

fn decode_field_segment(raw: &str) -> Result<(String, bool), ClaimsError> {
    if let Some(numeric_field) = raw.strip_prefix(NUMERIC_FIELD_ESCAPE) {
        if numeric_field.is_empty() || !is_decimal_index(numeric_field) {
            return Err(ClaimsError::InvalidInput(
                ClaimsInvalidReason::InvalidClaimPathSegment,
            ));
        }
        return Ok((numeric_field.to_owned(), true));
    }

    let mut out = String::with_capacity(raw.len());
    let mut characters = raw.chars();
    while let Some(character) = characters.next() {
        if character != '~' {
            out.push(character);
            continue;
        }
        match characters.next() {
            Some('0') => out.push('~'),
            Some('1') => out.push('/'),
            Some(_) | None => {
                return Err(ClaimsError::InvalidInput(
                    ClaimsInvalidReason::InvalidClaimPathSegment,
                ));
            }
        }
    }
    Ok((out, false))
}

fn validate_field_segment(field: &str, numeric_field_escape: bool) -> Result<(), ClaimsError> {
    if field.is_empty()
        || field.len() > MAX_CLAIM_PATH_SEGMENT_BYTES
        || field == "."
        || field == ".."
        || field == "*"
        || field.bytes().any(|byte| byte.is_ascii_control())
        || (!numeric_field_escape && field.bytes().all(|byte| byte.is_ascii_digit()))
    {
        return Err(ClaimsError::InvalidInput(
            ClaimsInvalidReason::InvalidClaimPathSegment,
        ));
    }
    Ok(())
}

/// Escape an object field for use as one canonical path segment.
pub fn escape_field_segment(field: &str) -> String {
    if !field.is_empty() && field.bytes().all(|byte| byte.is_ascii_digit()) {
        let mut out = String::new();
        out.push_str(NUMERIC_FIELD_ESCAPE);
        out.push_str(field);
        return out;
    }

    let mut out = String::with_capacity(field.len());
    for character in field.chars() {
        match character {
            '~' => out.push_str("~0"),
            '/' => out.push_str("~1"),
            value => out.push(value),
        }
    }
    out
}
