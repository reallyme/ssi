// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

fn zeroize_cbor_value(value: &mut Value) {
    match value {
        Value::Bytes(bytes) => bytes.zeroize(),
        Value::Text(text) => text.zeroize(),
        Value::Array(items) => {
            for item in items {
                zeroize_cbor_value(item);
            }
        }
        Value::Map(entries) => {
            for (key, item) in entries {
                zeroize_cbor_value(key);
                zeroize_cbor_value(item);
            }
        }
        Value::Tag(_, item) => zeroize_cbor_value(item),
        _ => {}
    }
}

#[cfg(test)]
#[path = "../cbor_zeroization_tests.rs"]
mod zeroization_tests;
