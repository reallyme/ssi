// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::collections::BTreeMap;

use serde_json::Value;
use zeroize::Zeroize;

pub(crate) fn zeroize_json_value(value: &mut Value) {
    match value {
        Value::String(text) => text.zeroize(),
        Value::Array(values) => {
            for value in values {
                zeroize_json_value(value);
            }
        }
        Value::Object(values) => {
            for (mut key, mut value) in core::mem::take(values) {
                key.zeroize();
                zeroize_json_value(&mut value);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

pub(crate) fn zeroize_option(value: &mut Option<String>) {
    if let Some(text) = value {
        text.zeroize();
    }
    *value = None;
}

pub(crate) fn zeroize_string_map(values: &mut BTreeMap<String, String>) {
    for (mut key, mut value) in core::mem::take(values) {
        key.zeroize();
        value.zeroize();
    }
}

pub(crate) fn zeroize_string_list(values: &mut Option<Vec<String>>) {
    if let Some(items) = values {
        for item in items.iter_mut() {
            item.zeroize();
        }
        items.clear();
    }
    *values = None;
}
