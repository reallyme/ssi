// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::collections::BTreeMap;

use serde_json::{Map, Value};
use zeroize::Zeroize;

pub(crate) const MAX_COMPACT_SD_JWT_BYTES: usize = 2 * 1024 * 1024;
pub(crate) const MAX_SD_JWT_DISCLOSURES: usize = 256;
pub(crate) const MAX_SD_JWT_DISCLOSURE_BYTES: usize = 4096;
pub(crate) const MAX_SD_JWT_JSON_BYTES: usize = 3 * 1024 * 1024;
pub(crate) const MAX_SD_JWT_JSON_DEPTH: usize = 32;
pub(crate) const MAX_SD_JWT_JSON_NODES: usize = 16_384;
pub(crate) const MAX_SD_JWT_CONTAINER_ENTRIES: usize = 1024;
pub(crate) const MAX_SD_JWT_STRING_BYTES: usize = 64 * 1024;
pub(crate) const MAX_SD_JWT_ISSUER_BYTES: usize = 4096;
pub(crate) const MAX_SD_JWT_SALT_BYTES: usize = 64;

pub(crate) fn compact_capacity(
    issuer_signed_jwt: &str,
    disclosures: &[String],
    kb_jwt: Option<&str>,
) -> Option<usize> {
    if issuer_signed_jwt.is_empty()
        || issuer_signed_jwt.split('.').count() != 3
        || disclosures.len() > MAX_SD_JWT_DISCLOSURES
        || disclosures
            .iter()
            .any(|value| value.is_empty() || value.len() > MAX_SD_JWT_DISCLOSURE_BYTES)
        || kb_jwt.is_some_and(|value| value.is_empty() || value.split('.').count() != 3)
    {
        return None;
    }

    let mut total = issuer_signed_jwt.len().checked_add(1)?;
    for disclosure in disclosures {
        total = total.checked_add(disclosure.len())?.checked_add(1)?;
    }
    if let Some(value) = kb_jwt {
        total = total.checked_add(value.len())?;
    }

    (total <= MAX_COMPACT_SD_JWT_BYTES).then_some(total)
}

pub(crate) fn json_value_within_limits(value: &Value) -> bool {
    let mut nodes = 0usize;
    validate_json_value(value, 0, &mut nodes)
}

fn validate_json_value(value: &Value, depth: usize, nodes: &mut usize) -> bool {
    if depth > MAX_SD_JWT_JSON_DEPTH {
        return false;
    }
    let Some(next_nodes) = nodes.checked_add(1) else {
        return false;
    };
    if next_nodes > MAX_SD_JWT_JSON_NODES {
        return false;
    }
    *nodes = next_nodes;

    match value {
        Value::String(text) => text.len() <= MAX_SD_JWT_STRING_BYTES,
        Value::Array(values) => {
            values.len() <= MAX_SD_JWT_CONTAINER_ENTRIES
                && values.iter().all(|item| {
                    depth
                        .checked_add(1)
                        .is_some_and(|next_depth| validate_json_value(item, next_depth, nodes))
                })
        }
        Value::Object(values) => {
            values.len() <= MAX_SD_JWT_CONTAINER_ENTRIES
                && values.iter().all(|(key, item)| {
                    key.len() <= MAX_SD_JWT_STRING_BYTES
                        && depth
                            .checked_add(1)
                            .is_some_and(|next_depth| validate_json_value(item, next_depth, nodes))
                })
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => true,
    }
}

pub(crate) fn zeroize_json_value(value: &mut Value) {
    match value {
        Value::String(text) => text.zeroize(),
        Value::Array(values) => {
            for value in values {
                zeroize_json_value(value);
            }
        }
        Value::Object(values) => zeroize_json_map(values),
        Value::Bool(_) | Value::Number(_) => *value = Value::Null,
        Value::Null => {}
    }
}

pub(crate) fn zeroize_json_map(values: &mut Map<String, Value>) {
    for (mut key, mut value) in core::mem::take(values) {
        key.zeroize();
        zeroize_json_value(&mut value);
    }
}

pub(crate) fn zeroize_json_btree(values: &mut BTreeMap<String, Value>) {
    for (mut key, mut value) in core::mem::take(values) {
        key.zeroize();
        zeroize_json_value(&mut value);
    }
}

pub(crate) fn zeroize_strings(values: &mut Vec<String>) {
    for value in values.iter_mut() {
        value.zeroize();
    }
    values.clear();
}
