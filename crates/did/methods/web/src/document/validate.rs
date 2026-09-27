// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! DID Core data-model validation for resolved did:web documents.

use std::collections::BTreeSet;

use serde_json::{Map, Value};
use url::Url;

use super::DidWebDocumentLimits;
use crate::did_url::{validate_absolute_did_url, validate_base_did};
use crate::error::{DidWebError, DidWebErrorReason};
use crate::method::{parse_did_web, DidWebIdentifier};

const DID_CORE_CONTEXT: &str = "https://www.w3.org/ns/did/v1";
const MAX_PUBLIC_KEY_MULTIBASE_BYTES: usize = 8 * 1024;
const MAX_MULTICODEC_VARINT_BYTES: usize = 10;
const RELATIONSHIPS: [&str; 5] = [
    "authentication",
    "assertionMethod",
    "keyAgreement",
    "capabilityInvocation",
    "capabilityDelegation",
];

pub(super) fn validate_shape_limits(
    value: &Value,
    limits: DidWebDocumentLimits,
) -> Result<(), DidWebError> {
    let mut stack = vec![(value, 1usize)];
    let mut nodes = 0usize;
    while let Some((current, depth)) = stack.pop() {
        nodes = nodes
            .checked_add(1)
            .ok_or(DidWebError::new(DidWebErrorReason::JsonDepthExceeded))?;
        if nodes > limits.max_nodes || depth > limits.max_depth {
            return Err(DidWebError::new(DidWebErrorReason::JsonDepthExceeded));
        }
        let next_depth = depth
            .checked_add(1)
            .ok_or(DidWebError::new(DidWebErrorReason::JsonDepthExceeded))?;
        match current {
            Value::Array(values) => stack.extend(values.iter().map(|item| (item, next_depth))),
            Value::Object(values) => {
                stack.extend(values.values().map(|item| (item, next_depth)));
            }
            Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
        }
    }
    Ok(())
}

pub(super) fn validate_document(
    requested: &DidWebIdentifier,
    value: &Value,
) -> Result<(), DidWebError> {
    let object = value
        .as_object()
        .ok_or(DidWebError::new(DidWebErrorReason::InvalidDocument))?;
    let id = required_string(object, "id", DidWebErrorReason::InvalidDocument)?;
    let parsed_id = parse_did_web(id)?;
    if parsed_id.as_str() != requested.as_str() {
        return Err(DidWebError::new(
            DidWebErrorReason::DocumentIdentifierMismatch,
        ));
    }
    validate_context(object)?;
    validate_controllers(object.get("controller"))?;
    validate_also_known_as(object.get("alsoKnownAs"))?;

    let did = requested.as_str();
    let mut method_ids = BTreeSet::new();
    if let Some(methods) = object.get("verificationMethod") {
        let methods = methods.as_array().ok_or(DidWebError::new(
            DidWebErrorReason::InvalidVerificationMethod,
        ))?;
        for method in methods {
            validate_verification_method(did, method, &mut method_ids)?;
        }
    }
    for relationship in RELATIONSHIPS {
        validate_relationship_set(object.get(relationship))?;
        validate_relationship_embedded(did, object.get(relationship), &mut method_ids)?;
    }
    for relationship in RELATIONSHIPS {
        validate_relationship_references(did, object.get(relationship), &method_ids)?;
    }
    validate_services(did, object.get("service"), &mut method_ids)?;
    validate_all_did_urls(value)?;
    Ok(())
}

fn validate_context(object: &Map<String, Value>) -> Result<(), DidWebError> {
    let Some(context) = object.get("@context") else {
        return Ok(());
    };
    let valid = match context {
        Value::String(value) => value == DID_CORE_CONTEXT,
        Value::Array(values) => {
            values.first().and_then(Value::as_str) == Some(DID_CORE_CONTEXT)
                && values
                    .iter()
                    .skip(1)
                    .all(|value| matches!(value, Value::String(_) | Value::Object(_)))
        }
        _ => false,
    };
    if !valid {
        return Err(DidWebError::new(DidWebErrorReason::InvalidDocument));
    }
    Ok(())
}

fn validate_controllers(value: Option<&Value>) -> Result<(), DidWebError> {
    let Some(value) = value else {
        return Ok(());
    };
    match value {
        Value::String(controller) => {
            validate_base_did(controller, DidWebErrorReason::InvalidController)
        }
        Value::Array(controllers) if !controllers.is_empty() => {
            let mut unique = BTreeSet::new();
            for controller in controllers {
                let controller = controller
                    .as_str()
                    .ok_or(DidWebError::new(DidWebErrorReason::InvalidController))?;
                validate_base_did(controller, DidWebErrorReason::InvalidController)?;
                if !unique.insert(controller) {
                    return Err(DidWebError::new(DidWebErrorReason::InvalidController));
                }
            }
            Ok(())
        }
        _ => Err(DidWebError::new(DidWebErrorReason::InvalidController)),
    }
}

fn validate_also_known_as(value: Option<&Value>) -> Result<(), DidWebError> {
    let Some(value) = value else {
        return Ok(());
    };
    let aliases = value
        .as_array()
        .filter(|aliases| !aliases.is_empty())
        .ok_or(DidWebError::new(DidWebErrorReason::InvalidDocument))?;
    let mut unique = BTreeSet::new();
    for alias in aliases {
        let alias = alias
            .as_str()
            .filter(|alias| !alias.is_empty())
            .ok_or(DidWebError::new(DidWebErrorReason::InvalidDocument))?;
        validate_absolute_uri(alias, DidWebErrorReason::InvalidDocument)?;
        if !unique.insert(alias) {
            return Err(DidWebError::new(DidWebErrorReason::InvalidDocument));
        }
    }
    Ok(())
}

fn validate_verification_method(
    did: &str,
    value: &Value,
    method_ids: &mut BTreeSet<String>,
) -> Result<(), DidWebError> {
    let object = value.as_object().ok_or(DidWebError::new(
        DidWebErrorReason::InvalidVerificationMethod,
    ))?;
    let id = required_string(object, "id", DidWebErrorReason::InvalidVerificationMethod)?;
    validate_absolute_did_url(id, true)?;
    if !did_url_belongs_to(id, did) {
        return Err(DidWebError::new(
            DidWebErrorReason::DocumentIdentifierMismatch,
        ));
    }
    if !method_ids.insert(id.to_owned()) {
        return Err(DidWebError::new(
            DidWebErrorReason::InvalidVerificationMethod,
        ));
    }
    let method_type =
        required_string(object, "type", DidWebErrorReason::InvalidVerificationMethod)?;
    if method_type.is_empty() {
        return Err(DidWebError::new(
            DidWebErrorReason::InvalidVerificationMethod,
        ));
    }
    let controller = required_string(
        object,
        "controller",
        DidWebErrorReason::InvalidVerificationMethod,
    )?;
    validate_base_did(controller, DidWebErrorReason::InvalidVerificationMethod)?;
    validate_public_key_material(method_type, object)
}

include!("validate/key_material.rs");

fn validate_relationship_set(value: Option<&Value>) -> Result<(), DidWebError> {
    let Some(value) = value else {
        return Ok(());
    };
    let entries = value
        .as_array()
        .filter(|entries| !entries.is_empty())
        .ok_or(DidWebError::new(
            DidWebErrorReason::UnresolvedRelationshipReference,
        ))?;
    let mut unique = BTreeSet::new();
    for entry in entries {
        let identifier = match entry {
            Value::String(identifier) => identifier.as_str(),
            Value::Object(object) => {
                required_string(object, "id", DidWebErrorReason::InvalidVerificationMethod)?
            }
            _ => {
                return Err(DidWebError::new(
                    DidWebErrorReason::UnresolvedRelationshipReference,
                ));
            }
        };
        if !unique.insert(identifier) {
            return Err(DidWebError::new(
                DidWebErrorReason::UnresolvedRelationshipReference,
            ));
        }
    }
    Ok(())
}

fn validate_relationship_embedded(
    did: &str,
    value: Option<&Value>,
    method_ids: &mut BTreeSet<String>,
) -> Result<(), DidWebError> {
    let Some(value) = value else {
        return Ok(());
    };
    let entries = value.as_array().ok_or(DidWebError::new(
        DidWebErrorReason::UnresolvedRelationshipReference,
    ))?;
    for entry in entries {
        if entry.as_str().is_none() {
            validate_verification_method(did, entry, method_ids)?;
        }
    }
    Ok(())
}

fn validate_relationship_references(
    did: &str,
    value: Option<&Value>,
    method_ids: &BTreeSet<String>,
) -> Result<(), DidWebError> {
    let Some(value) = value else {
        return Ok(());
    };
    let entries = value.as_array().ok_or(DidWebError::new(
        DidWebErrorReason::UnresolvedRelationshipReference,
    ))?;
    for reference in entries.iter().filter_map(Value::as_str) {
        validate_absolute_did_url(reference, true)?;
        if !did_url_belongs_to(reference, did) || !method_ids.contains(reference) {
            return Err(DidWebError::new(
                DidWebErrorReason::UnresolvedRelationshipReference,
            ));
        }
    }
    Ok(())
}

fn validate_services(
    did: &str,
    value: Option<&Value>,
    resource_ids: &mut BTreeSet<String>,
) -> Result<(), DidWebError> {
    let Some(value) = value else {
        return Ok(());
    };
    let services = value
        .as_array()
        .ok_or(DidWebError::new(DidWebErrorReason::InvalidService))?;
    for service in services {
        let object = service
            .as_object()
            .ok_or(DidWebError::new(DidWebErrorReason::InvalidService))?;
        let id = required_string(object, "id", DidWebErrorReason::InvalidService)?;
        validate_absolute_uri(id, DidWebErrorReason::InvalidService)?;
        if id.starts_with("did:") {
            validate_absolute_did_url(id, true)?;
            if !did_url_belongs_to(id, did) {
                return Err(DidWebError::new(
                    DidWebErrorReason::DocumentIdentifierMismatch,
                ));
            }
        }
        if !resource_ids.insert(id.to_owned()) {
            return Err(DidWebError::new(DidWebErrorReason::InvalidService));
        }
        validate_service_types(object.get("type"))?;
        validate_service_endpoint(object.get("serviceEndpoint"))?;
    }
    Ok(())
}

fn validate_service_types(value: Option<&Value>) -> Result<(), DidWebError> {
    let Some(value) = value else {
        return Err(DidWebError::new(DidWebErrorReason::InvalidService));
    };
    match value {
        Value::String(value) if !value.is_empty() => Ok(()),
        Value::Array(values) if !values.is_empty() => {
            let mut unique = BTreeSet::new();
            for value in values {
                let value = value
                    .as_str()
                    .filter(|value| !value.is_empty())
                    .ok_or(DidWebError::new(DidWebErrorReason::InvalidService))?;
                if !unique.insert(value) {
                    return Err(DidWebError::new(DidWebErrorReason::InvalidService));
                }
            }
            Ok(())
        }
        _ => Err(DidWebError::new(DidWebErrorReason::InvalidService)),
    }
}

fn validate_service_endpoint(value: Option<&Value>) -> Result<(), DidWebError> {
    let Some(value) = value else {
        return Err(DidWebError::new(DidWebErrorReason::InvalidService));
    };
    match value {
        Value::String(uri) => validate_absolute_uri(uri, DidWebErrorReason::InvalidService),
        Value::Object(_) => Ok(()),
        Value::Array(values) if !values.is_empty() => {
            for (index, value) in values.iter().enumerate() {
                let preceding = values
                    .get(..index)
                    .ok_or(DidWebError::new(DidWebErrorReason::InvalidService))?;
                if preceding.contains(value) {
                    return Err(DidWebError::new(DidWebErrorReason::InvalidService));
                }
                match value {
                    Value::String(uri) => {
                        validate_absolute_uri(uri, DidWebErrorReason::InvalidService)?;
                    }
                    Value::Object(_) => {}
                    _ => return Err(DidWebError::new(DidWebErrorReason::InvalidService)),
                }
            }
            Ok(())
        }
        _ => Err(DidWebError::new(DidWebErrorReason::InvalidService)),
    }
}

fn validate_absolute_uri(value: &str, reason: DidWebErrorReason) -> Result<(), DidWebError> {
    if value.is_empty() || Url::parse(value).is_err() {
        return Err(DidWebError::new(reason));
    }
    Ok(())
}

/// Return true when an absolute DID URL's base DID is exactly `did`.
fn did_url_belongs_to(url: &str, did: &str) -> bool {
    url == did
        || url
            .strip_prefix(did)
            .is_some_and(|suffix| suffix.starts_with(['/', '?', '#']))
}

fn validate_all_did_urls(value: &Value) -> Result<(), DidWebError> {
    let mut stack = vec![value];
    while let Some(current) = stack.pop() {
        match current {
            Value::String(candidate) if candidate.starts_with("did:") => {
                validate_absolute_did_url(candidate, false)?;
            }
            Value::Array(values) => stack.extend(values.iter()),
            Value::Object(values) => stack.extend(values.values()),
            Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
        }
    }
    Ok(())
}

fn required_string<'a>(
    object: &'a Map<String, Value>,
    key: &str,
    reason: DidWebErrorReason,
) -> Result<&'a str, DidWebError> {
    object
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or(DidWebError::new(reason))
}
