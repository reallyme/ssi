// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{zeroize_cbor_value, Value};

#[test]
fn recursive_cbor_cleanup_scrubs_nested_text_and_bytes() {
    let mut value = Value::Map(vec![(
        Value::Text("pii-key".to_owned()),
        Value::Array(vec![
            Value::Text("personal-name".to_owned()),
            Value::Tag(24, Box::new(Value::Bytes(vec![1, 2, 3, 4]))),
        ]),
    )]);

    zeroize_cbor_value(&mut value);

    assert!(matches!(
        &value,
        Value::Map(entries)
            if matches!(
                entries.as_slice(),
                [(Value::Text(key), Value::Array(items))]
                    if key.is_empty()
                        && matches!(items.first(), Some(Value::Text(text)) if text.is_empty())
                        && matches!(items.get(1), Some(Value::Tag(24, inner)) if matches!(inner.as_ref(), Value::Bytes(bytes) if bytes.is_empty()))
            )
    ));
}
