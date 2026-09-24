// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

fn claim_value_to_json(value: &ClaimValue) -> JsonValue {
    match value {
        ClaimValue::Null => JsonValue::Null,
        ClaimValue::Boolean(value) => JsonValue::Bool(*value),
        ClaimValue::String(value) => JsonValue::String(value.clone()),
        ClaimValue::Signed(value) => JsonValue::Number(serde_json::Number::from(*value)),
        ClaimValue::Unsigned(value) => JsonValue::Number(serde_json::Number::from(*value)),
        ClaimValue::Decimal(value) => JsonValue::String(value.as_str().to_owned()),
        ClaimValue::Bytes(value) => JsonValue::Array(
            value
                .iter()
                .map(|byte| JsonValue::Number(serde_json::Number::from(*byte)))
                .collect(),
        ),
        ClaimValue::Date(value) => JsonValue::String(value.as_str().to_owned()),
        ClaimValue::DateTime(value) => JsonValue::String(value.as_str().to_owned()),
        ClaimValue::Array(values) => {
            JsonValue::Array(values.iter().map(claim_value_to_json).collect())
        }
        ClaimValue::Object(values) => {
            let mut out = JsonMap::new();
            for (key, value) in values {
                out.insert(key.clone(), claim_value_to_json(value));
            }
            JsonValue::Object(out)
        }
    }
}

fn zeroize_json_value(value: &mut JsonValue) {
    match value {
        JsonValue::Null => {}
        JsonValue::Bool(boolean) => boolean.zeroize(),
        JsonValue::Number(_) => {
            // serde_json numbers are inline under the workspace feature set.
            // Replacing the value clears their typed representation.
            *value = JsonValue::Null;
        }
        JsonValue::String(string) => string.zeroize(),
        JsonValue::Array(values) => {
            for value in values.iter_mut() {
                zeroize_json_value(value);
            }
            values.clear();
        }
        JsonValue::Object(values) => {
            let owned = core::mem::take(values);
            for (mut key, mut value) in owned {
                key.zeroize();
                zeroize_json_value(&mut value);
            }
        }
    }
}

fn clone_claim_value(value: &ClaimValue) -> Result<ClaimValue, ClaimsError> {
    Ok(match value {
        ClaimValue::Null => ClaimValue::Null,
        ClaimValue::Boolean(value) => ClaimValue::Boolean(*value),
        ClaimValue::String(value) => ClaimValue::String(value.clone()),
        ClaimValue::Signed(value) => ClaimValue::Signed(*value),
        ClaimValue::Unsigned(value) => ClaimValue::Unsigned(*value),
        ClaimValue::Decimal(value) => {
            ClaimValue::Decimal(crate::ClaimDecimal::new(value.as_str().to_owned())?)
        }
        ClaimValue::Bytes(value) => ClaimValue::Bytes(value.clone()),
        ClaimValue::Date(value) => {
            ClaimValue::Date(crate::ClaimDate::new(value.as_str().to_owned())?)
        }
        ClaimValue::DateTime(value) => {
            ClaimValue::DateTime(crate::ClaimDateTime::new(value.as_str().to_owned())?)
        }
        ClaimValue::Array(values) => {
            let mut out = Vec::with_capacity(values.len());
            for value in values {
                out.push(clone_claim_value(value)?);
            }
            ClaimValue::Array(out)
        }
        ClaimValue::Object(values) => {
            let mut out = BTreeMap::new();
            for (key, value) in values {
                out.insert(key.clone(), clone_claim_value(value)?);
            }
            ClaimValue::Object(out)
        }
    })
}
