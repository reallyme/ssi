// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

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
            // JSON object keys can themselves be identifying claim names. Taking the
            // map lets us clear both keys and values instead of only clearing values.
            for (mut key, mut value) in core::mem::take(values) {
                key.zeroize();
                zeroize_json_value(&mut value);
            }
        }
        Value::Bool(_) | Value::Number(_) => *value = Value::Null,
        Value::Null => {}
    }
}

pub(crate) fn zeroize_strings(values: &mut Vec<String>) {
    for value in values.iter_mut() {
        value.zeroize();
    }
    values.clear();
}
