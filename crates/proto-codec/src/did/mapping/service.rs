// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use buffa::MessageField;
use buffa_types::google::protobuf::{value::Kind, ListValue, Struct, Value};
use reallyme_did_types::Service as JsonService;
use reallyme_ssi_proto::generated::proto::meid::did::v1::Service as PbService;

use crate::did::DidProtoCodecError;

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
        serde_json::Value::Number(value) => Kind::NumberValue(
            value
                .as_f64()
                .ok_or(DidProtoCodecError::InvalidServiceEndpoint)?,
        ),
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
        Some(Kind::NumberValue(value)) => serde_json::Number::from_f64(*value)
            .map(serde_json::Value::Number)
            .ok_or(DidProtoCodecError::InvalidServiceEndpoint),
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
