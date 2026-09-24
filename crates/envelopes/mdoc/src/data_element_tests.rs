// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use ciborium::value::Value as CborValue;
use serde_json::json;

use super::decode_mdoc_data_element_json;

#[test]
fn projects_tagged_and_nested_mdoc_values_without_losing_types() {
    let value = CborValue::Map(vec![
        (
            CborValue::Text("birth_date".to_owned()),
            CborValue::Tag(1004, Box::new(CborValue::Text("1990-01-01".to_owned()))),
        ),
        (
            CborValue::Text("age_over_18".to_owned()),
            CborValue::Bool(true),
        ),
    ]);
    let mut encoded = Vec::new();
    let encoded_result = ciborium::ser::into_writer(&value, &mut encoded);
    assert!(encoded_result.is_ok());
    let projected = decode_mdoc_data_element_json(&encoded);
    assert!(projected.is_ok());
    if let Ok(projected) = projected {
        assert_eq!(
            projected.as_value(),
            &json!({"birth_date": "1990-01-01", "age_over_18": true})
        );
    }
}

#[test]
fn rejects_maps_that_cannot_be_addressed_by_json_claim_paths() {
    let value = CborValue::Map(vec![(CborValue::Integer(1.into()), CborValue::Null)]);
    let mut encoded = Vec::new();
    let encoded_result = ciborium::ser::into_writer(&value, &mut encoded);
    assert!(encoded_result.is_ok());
    assert!(decode_mdoc_data_element_json(&encoded).is_err());
}
