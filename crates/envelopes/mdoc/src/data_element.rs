// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Bounded mdoc data-element projection for JSON-path query evaluation.

use core::fmt;

use ciborium::value::Value as CborValue;
use serde_json::{Map as JsonMap, Number as JsonNumber, Value as JsonValue};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{MdocEnvelopeError, MdocInvalidInputReason};

/// A JSON-compatible mdoc data element whose identity data is wiped on drop.
pub struct MdocDataElementJson(JsonValue);

impl MdocDataElementJson {
    /// Borrow the projected JSON value for DCQL evaluation.
    #[must_use]
    pub const fn as_value(&self) -> &JsonValue {
        &self.0
    }
}

impl fmt::Debug for MdocDataElementJson {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MdocDataElementJson([REDACTED])")
    }
}

impl Zeroize for MdocDataElementJson {
    fn zeroize(&mut self) {
        zeroize_json_value(&mut self.0);
    }
}

impl Drop for MdocDataElementJson {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for MdocDataElementJson {}

/// Decode one already-bounded mdoc element value into a JSON-compatible view.
///
/// CBOR tags are semantic wrappers for values such as full-date and tdate, so
/// the projection retains their wrapped value. Byte strings become base64url
/// text, avoiding the large per-byte allocation cost of JSON number arrays.
/// Maps with non-text keys are rejected because DCQL
/// claim paths cannot address them without an ambiguous lossy conversion.
pub fn decode_mdoc_data_element_json(
    element_value_cbor: &[u8],
) -> Result<MdocDataElementJson, MdocEnvelopeError> {
    let value = crate::cbor::cbor_bytes_to_value(element_value_cbor)?;
    cbor_to_json(&value).map(MdocDataElementJson)
}

fn cbor_to_json(value: &CborValue) -> Result<JsonValue, MdocEnvelopeError> {
    match value {
        CborValue::Null => Ok(JsonValue::Null),
        CborValue::Bool(value) => Ok(JsonValue::Bool(*value)),
        CborValue::Integer(value) => {
            let value = i128::from(*value);
            if let Ok(signed) = i64::try_from(value) {
                return Ok(JsonValue::Number(JsonNumber::from(signed)));
            }
            let unsigned = u64::try_from(value).map_err(|_| projection_error())?;
            Ok(JsonValue::Number(JsonNumber::from(unsigned)))
        }
        CborValue::Float(value) => JsonNumber::from_f64(*value)
            .map(JsonValue::Number)
            .ok_or_else(projection_error),
        CborValue::Text(value) => Ok(JsonValue::String(value.clone())),
        CborValue::Bytes(value) => Ok(JsonValue::String(
            reallyme_codec::base64url::bytes_to_base64url(value),
        )),
        CborValue::Array(values) => values
            .iter()
            .map(cbor_to_json)
            .collect::<Result<Vec<_>, _>>()
            .map(JsonValue::Array),
        CborValue::Map(entries) => {
            let mut object = JsonMap::new();
            for (key, value) in entries {
                let CborValue::Text(key) = key else {
                    return Err(projection_error());
                };
                if object.insert(key.clone(), cbor_to_json(value)?).is_some() {
                    return Err(projection_error());
                }
            }
            Ok(JsonValue::Object(object))
        }
        CborValue::Tag(_, value) => cbor_to_json(value),
        _ => Err(projection_error()),
    }
}

fn zeroize_json_value(value: &mut JsonValue) {
    match value {
        JsonValue::String(value) => value.zeroize(),
        JsonValue::Array(values) => {
            for value in values {
                zeroize_json_value(value);
            }
        }
        JsonValue::Object(object) => {
            for (mut key, mut value) in core::mem::take(object) {
                key.zeroize();
                zeroize_json_value(&mut value);
            }
        }
        JsonValue::Null | JsonValue::Bool(_) | JsonValue::Number(_) => {
            *value = JsonValue::Null;
        }
    }
}

const fn projection_error() -> MdocEnvelopeError {
    MdocEnvelopeError::InvalidInput(MdocInvalidInputReason::MalformedIssuerSignedItem)
}

#[cfg(test)]
#[path = "data_element_tests.rs"]
mod tests;
