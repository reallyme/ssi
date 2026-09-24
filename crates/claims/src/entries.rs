// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::{
    ClaimPath, ClaimPathSegment, ClaimValue, ClaimsError, ClaimsInvalidReason,
    MAX_CLAIM_ARRAY_ITEMS, MAX_CLAIM_OBJECT_PROPERTIES,
};
use std::collections::BTreeMap;

/// One normalized claim value addressed by canonical claim path.
///
/// This is the preferred internal adapter shape for protobuf/Buffa transports:
/// generated models can map typed value oneofs into `ClaimValue` and carry the
/// canonical `/claims/...` selector separately, without first inventing a JSON
/// object representation.
#[derive(Debug, Eq, PartialEq)]
pub struct ClaimPathEntry {
    /// Canonical path identifying the claim value.
    pub path: ClaimPath,

    /// Normalized value at the path.
    pub value: ClaimValue,
}

/// Build a normalized root object from canonical path entries.
pub fn claim_value_from_path_entries<I>(entries: I) -> Result<ClaimValue, ClaimsError>
where
    I: IntoIterator<Item = ClaimPathEntry>,
{
    let mut root = ClaimValue::Object(BTreeMap::new());
    for entry in entries {
        insert_entry(&mut root, entry.path.segments(), entry.value)?;
    }
    Ok(root)
}

fn insert_entry(
    current: &mut ClaimValue,
    segments: &[ClaimPathSegment],
    value: ClaimValue,
) -> Result<(), ClaimsError> {
    let Some((first, rest)) = segments.split_first() else {
        return Err(ClaimsError::InvalidInput(
            ClaimsInvalidReason::InvalidClaimPath,
        ));
    };

    match first {
        ClaimPathSegment::Field(field) => insert_field(current, field.as_str(), rest, value),
        ClaimPathSegment::ArrayIndex(index) => insert_array_index(current, *index, rest, value),
    }
}

fn insert_field(
    current: &mut ClaimValue,
    field: &str,
    rest: &[ClaimPathSegment],
    value: ClaimValue,
) -> Result<(), ClaimsError> {
    let ClaimValue::Object(object) = current else {
        return Err(ClaimsError::InvalidInput(
            ClaimsInvalidReason::ParentChildClaimPathConflict,
        ));
    };
    if rest.is_empty() {
        if object.insert(field.to_owned(), value).is_some() {
            return Err(ClaimsError::InvalidInput(
                ClaimsInvalidReason::DuplicateClaimPath,
            ));
        }
        return Ok(());
    }

    if object.len() >= MAX_CLAIM_OBJECT_PROPERTIES && !object.contains_key(field) {
        return Err(ClaimsError::InvalidInput(
            ClaimsInvalidReason::ClaimValueLimitExceeded,
        ));
    }
    let next = object
        .entry(field.to_owned())
        .or_insert_with(|| container_for_next(&rest[0]));
    insert_entry(next, rest, value)
}

fn insert_array_index(
    current: &mut ClaimValue,
    index: u32,
    rest: &[ClaimPathSegment],
    value: ClaimValue,
) -> Result<(), ClaimsError> {
    let ClaimValue::Array(array) = current else {
        return Err(ClaimsError::InvalidInput(
            ClaimsInvalidReason::ParentChildClaimPathConflict,
        ));
    };
    let index = usize::try_from(index)
        .map_err(|_| ClaimsError::InvalidInput(ClaimsInvalidReason::InvalidClaimPathSegment))?;
    if index >= MAX_CLAIM_ARRAY_ITEMS {
        return Err(ClaimsError::InvalidInput(
            ClaimsInvalidReason::ClaimValueLimitExceeded,
        ));
    }
    if array.len() <= index {
        let target_len = index.checked_add(1).ok_or(ClaimsError::InvalidInput(
            ClaimsInvalidReason::ClaimValueLimitExceeded,
        ))?;
        array.resize_with(target_len, || ClaimValue::Null);
    }
    if rest.is_empty() {
        if !matches!(array[index], ClaimValue::Null) {
            return Err(ClaimsError::InvalidInput(
                ClaimsInvalidReason::DuplicateClaimPath,
            ));
        }
        array[index] = value;
        return Ok(());
    }

    if matches!(array[index], ClaimValue::Null) {
        array[index] = container_for_next(&rest[0]);
    }
    insert_entry(&mut array[index], rest, value)
}

fn container_for_next(segment: &ClaimPathSegment) -> ClaimValue {
    match segment {
        ClaimPathSegment::Field(_) => ClaimValue::Object(BTreeMap::new()),
        ClaimPathSegment::ArrayIndex(_) => ClaimValue::Array(Vec::new()),
    }
}
