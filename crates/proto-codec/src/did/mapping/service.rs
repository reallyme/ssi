// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use buffa::MessageField;
use buffa_types::google::protobuf::{value::Kind, ListValue, Struct, Value};
use reallyme_did_types::Service as JsonService;
use reallyme_ssi_proto::generated::proto::meid::did::v1::Service as PbService;

use crate::did::DidProtoCodecError;

/// Largest integer magnitude that `google.protobuf.Value.number_value` (an
/// IEEE 754 double) represents exactly: 2^53 - 1.
const MAX_EXACT_INTEGER: u64 = 9_007_199_254_740_991;

/// [`MAX_EXACT_INTEGER`] as a double; the value is exactly representable.
const MAX_EXACT_INTEGER_F64: f64 = 9_007_199_254_740_991.0;

/// JSON-domain service to did:me protobuf.
pub fn service_to_proto(s: &JsonService) -> Result<PbService, DidProtoCodecError> {
    Ok(PbService {
        id: s.id.clone(),
        r#type: s.service_type.clone(),
        service_endpoint: MessageField::some(json_value_to_proto(&s.service_endpoint)?),
        ..PbService::default()
    })
}

/// did:me protobuf service to JSON-domain model.
pub fn service_from_proto(p: &PbService) -> Result<JsonService, DidProtoCodecError> {
    Ok(JsonService {
        id: p.id.clone(),
        service_type: p.r#type.clone(),
        service_endpoint: match p.service_endpoint.as_option() {
            Some(value) => proto_value_to_json(value)?,
            None => serde_json::Value::Null,
        },
    })
}

fn json_value_to_proto(value: &serde_json::Value) -> Result<Value, DidProtoCodecError> {
    let kind = match value {
        serde_json::Value::Null => Kind::NullValue(Default::default()),
        serde_json::Value::Bool(value) => Kind::BoolValue(*value),
        serde_json::Value::Number(value) => Kind::NumberValue(json_number_to_f64(value)?),
        serde_json::Value::String(value) => Kind::StringValue(value.clone()),
        serde_json::Value::Array(items) => Kind::ListValue(Box::new(ListValue {
            values: items
                .iter()
                .map(json_value_to_proto)
                .collect::<Result<_, _>>()?,
            ..ListValue::default()
        })),
        serde_json::Value::Object(map) => {
            let mut object = Struct::default();
            for (key, item) in map {
                object
                    .fields
                    .insert(key.clone(), json_value_to_proto(item)?);
            }
            Kind::StructValue(Box::new(object))
        }
    };

    Ok(Value {
        kind: Some(kind),
        ..Value::default()
    })
}

fn proto_value_to_json(value: &Value) -> Result<serde_json::Value, DidProtoCodecError> {
    match value.kind.as_ref() {
        Some(Kind::NullValue(_)) | None => Ok(serde_json::Value::Null),
        Some(Kind::BoolValue(value)) => Ok(serde_json::Value::Bool(*value)),
        Some(Kind::NumberValue(value)) => f64_to_json_number(*value).map(serde_json::Value::Number),
        Some(Kind::StringValue(value)) => Ok(serde_json::Value::String(value.clone())),
        Some(Kind::ListValue(list)) => Ok(serde_json::Value::Array(
            list.values
                .iter()
                .map(proto_value_to_json)
                .collect::<Result<_, _>>()?,
        )),
        Some(Kind::StructValue(object)) => {
            let mut out = serde_json::Map::new();
            for (key, item) in &object.fields {
                out.insert(key.clone(), proto_value_to_json(item)?);
            }
            Ok(serde_json::Value::Object(out))
        }
    }
}

/// Convert a JSON number into a protobuf double without silent precision loss.
///
/// Integers outside the exactly representable double range are rejected
/// instead of being rounded.
fn json_number_to_f64(value: &serde_json::Number) -> Result<f64, DidProtoCodecError> {
    let integer_exact = if let Some(integer) = value.as_i64() {
        integer.unsigned_abs() <= MAX_EXACT_INTEGER
    } else if let Some(integer) = value.as_u64() {
        integer <= MAX_EXACT_INTEGER
    } else {
        true
    };
    if !integer_exact {
        return Err(DidProtoCodecError::InvalidServiceEndpoint);
    }
    value
        .as_f64()
        .filter(|number| number.is_finite())
        .ok_or(DidProtoCodecError::InvalidServiceEndpoint)
}

/// Convert a protobuf double into a JSON number, restoring integer form for
/// integral values in the exactly representable range.
fn f64_to_json_number(value: f64) -> Result<serde_json::Number, DidProtoCodecError> {
    let integral = value.is_finite()
        && value.fract() == 0.0
        && value.abs() <= MAX_EXACT_INTEGER_F64
        && !(value == 0.0 && value.is_sign_negative());
    if integral {
        // Exact: the value is integral and its magnitude is at most 2^53 - 1,
        // so the conversion neither truncates nor rounds.
        let integer = value as i64;
        return Ok(serde_json::Number::from(integer));
    }
    serde_json::Number::from_f64(value).ok_or(DidProtoCodecError::InvalidServiceEndpoint)
}
