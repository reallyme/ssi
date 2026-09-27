// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! DID Core service validation for EBSI registry documents.

use std::collections::BTreeSet;

use serde_json::{Map, Value};
use url::Url;

use crate::{DidEbsiError, DidEbsiErrorReason};

pub(super) fn validate_services(object: &Map<String, Value>) -> Result<(), DidEbsiError> {
    let Some(services) = object.get("service") else {
        return Ok(());
    };
    let services = services
        .as_array()
        .ok_or(DidEbsiError::new(DidEbsiErrorReason::InvalidDocument))?;
    let mut identifiers = BTreeSet::new();
    for value in services {
        let service = value
            .as_object()
            .ok_or(DidEbsiError::new(DidEbsiErrorReason::InvalidDocument))?;
        let identifier = required_string(service, "id")?;
        if Url::parse(identifier).is_err() || !identifiers.insert(identifier) {
            return Err(DidEbsiError::new(DidEbsiErrorReason::InvalidDocument));
        }
        validate_service_types(service.get("type"))?;
        validate_service_endpoint(service.get("serviceEndpoint"))?;
    }
    Ok(())
}

fn validate_service_types(value: Option<&Value>) -> Result<(), DidEbsiError> {
    match value {
        Some(Value::String(value)) if !value.is_empty() => Ok(()),
        Some(Value::Array(values)) if !values.is_empty() => {
            let mut unique = BTreeSet::new();
            for value in values {
                let value = value
                    .as_str()
                    .filter(|value| !value.is_empty())
                    .ok_or(DidEbsiError::new(DidEbsiErrorReason::InvalidDocument))?;
                if !unique.insert(value) {
                    return Err(DidEbsiError::new(DidEbsiErrorReason::InvalidDocument));
                }
            }
            Ok(())
        }
        _ => Err(DidEbsiError::new(DidEbsiErrorReason::InvalidDocument)),
    }
}

fn validate_service_endpoint(value: Option<&Value>) -> Result<(), DidEbsiError> {
    match value {
        Some(Value::String(uri)) if Url::parse(uri).is_ok() => Ok(()),
        Some(Value::Object(_)) => Ok(()),
        Some(Value::Array(values)) if !values.is_empty() => {
            for (index, value) in values.iter().enumerate() {
                let preceding = values
                    .get(..index)
                    .ok_or(DidEbsiError::new(DidEbsiErrorReason::InvalidDocument))?;
                if preceding.contains(value) {
                    return Err(DidEbsiError::new(DidEbsiErrorReason::InvalidDocument));
                }
                match value {
                    Value::String(uri) if Url::parse(uri).is_ok() => {}
                    Value::Object(_) => {}
                    _ => return Err(DidEbsiError::new(DidEbsiErrorReason::InvalidDocument)),
                }
            }
            Ok(())
        }
        _ => Err(DidEbsiError::new(DidEbsiErrorReason::InvalidDocument)),
    }
}

fn required_string<'a>(
    object: &'a Map<String, Value>,
    name: &str,
) -> Result<&'a str, DidEbsiError> {
    object
        .get(name)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or(DidEbsiError::new(DidEbsiErrorReason::InvalidDocument))
}
