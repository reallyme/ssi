// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Pure did:web DID-document parsing and validation.

use std::collections::BTreeSet;

use serde_json::{Map, Value};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::did_url::{validate_absolute_did_url, validate_base_did};
use crate::error::{DidWebError, DidWebErrorReason};
use crate::method::{parse_did_web, DidWebIdentifier};

const DID_CORE_CONTEXT: &str = "https://www.w3.org/ns/did/v1";
const RELATIONSHIPS: [&str; 5] = [
    "authentication",
    "assertionMethod",
    "keyAgreement",
    "capabilityInvocation",
    "capabilityDelegation",
];
/// JWK members that carry private or symmetric key material (RFC 7518 §6).
const PRIVATE_JWK_MEMBERS: [&str; 8] = ["d", "p", "q", "dp", "dq", "qi", "oth", "k"];

/// Explicit limits applied before a network response becomes a DID document.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DidWebDocumentLimits {
    /// Maximum encoded JSON bytes.
    pub max_bytes: usize,
    /// Maximum JSON container nesting depth.
    pub max_depth: usize,
    /// Maximum total JSON values, including scalar leaves.
    pub max_nodes: usize,
}

impl Default for DidWebDocumentLimits {
    fn default() -> Self {
        Self {
            max_bytes: 1024 * 1024,
            max_depth: 32,
            max_nodes: 4096,
        }
    }
}

/// Validated did:web JSON document with deterministic drop cleanup.
pub struct DidWebDocument {
    value: Value,
    encoded: Vec<u8>,
}

impl DidWebDocument {
    /// Borrow the validated JSON value.
    #[must_use]
    pub fn as_json(&self) -> &Value {
        &self.value
    }

    /// Borrow the validated document identifier.
    #[must_use]
    pub fn id(&self) -> Option<&str> {
        self.value.get("id").and_then(Value::as_str)
    }

    /// Borrow the bounded encoded JSON supplied at the validated boundary.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.encoded
    }
}

impl core::fmt::Debug for DidWebDocument {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("DidWebDocument(<redacted>)")
    }
}

impl Zeroize for DidWebDocument {
    fn zeroize(&mut self) {
        zeroize_json(&mut self.value);
        self.encoded.zeroize();
        self.encoded.clear();
    }
}

impl Drop for DidWebDocument {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for DidWebDocument {}

/// Parse and validate a bounded did:web document against the requested DID.
pub fn parse_and_validate_did_web_document(
    requested: &DidWebIdentifier,
    bytes: &[u8],
    limits: DidWebDocumentLimits,
) -> Result<DidWebDocument, DidWebError> {
    if bytes.is_empty() || bytes.len() > limits.max_bytes {
        return Err(DidWebError::new(DidWebErrorReason::ResponseTooLarge));
    }
    identity_core_primitives::validate_json::validate_json(bytes)
        .map_err(|_| DidWebError::new(DidWebErrorReason::InvalidDocument))?;
    let value: Value = serde_json::from_slice(bytes)
        .map_err(|_| DidWebError::new(DidWebErrorReason::InvalidDocument))?;
    validate_shape_limits(&value, limits)?;
    validate_document(requested, &value)?;
    Ok(DidWebDocument {
        value,
        encoded: bytes.to_vec(),
    })
}

fn validate_shape_limits(value: &Value, limits: DidWebDocumentLimits) -> Result<(), DidWebError> {
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

fn validate_document(requested: &DidWebIdentifier, value: &Value) -> Result<(), DidWebError> {
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
        validate_relationship_embedded(did, object.get(relationship), &mut method_ids)?;
    }
    for relationship in RELATIONSHIPS {
        validate_relationship_references(object.get(relationship), &method_ids)?;
    }
    validate_services(did, object.get("service"), &mut method_ids)?;
    validate_all_did_urls(value)?;
    Ok(())
}

fn validate_context(object: &Map<String, Value>) -> Result<(), DidWebError> {
    let Some(context) = object.get("@context") else {
        return Ok(());
    };
    let contains_did_context = match context {
        Value::String(value) => value == DID_CORE_CONTEXT,
        Value::Array(values) => values
            .iter()
            .any(|value| value.as_str() == Some(DID_CORE_CONTEXT)),
        _ => false,
    };
    if !contains_did_context {
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
            for controller in controllers {
                let controller = controller
                    .as_str()
                    .ok_or(DidWebError::new(DidWebErrorReason::InvalidController))?;
                validate_base_did(controller, DidWebErrorReason::InvalidController)?;
            }
            Ok(())
        }
        _ => Err(DidWebError::new(DidWebErrorReason::InvalidController)),
    }
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
    validate_public_key_material(object)
}

fn validate_public_key_material(object: &Map<String, Value>) -> Result<(), DidWebError> {
    let multibase = object.get("publicKeyMultibase");
    let jwk = object.get("publicKeyJwk");
    let account = object.get("blockchainAccountId");
    let count = usize::from(multibase.is_some())
        .checked_add(usize::from(jwk.is_some()))
        .and_then(|value| value.checked_add(usize::from(account.is_some())))
        .ok_or(DidWebError::new(
            DidWebErrorReason::InvalidVerificationMethod,
        ))?;
    if count != 1 {
        return Err(DidWebError::new(
            DidWebErrorReason::InvalidVerificationMethod,
        ));
    }
    if let Some(value) = multibase.or(account) {
        if value.as_str().is_none_or(str::is_empty) {
            return Err(DidWebError::new(
                DidWebErrorReason::InvalidVerificationMethod,
            ));
        }
    }
    if let Some(value) = jwk {
        let key = value.as_object().ok_or(DidWebError::new(
            DidWebErrorReason::InvalidVerificationMethod,
        ))?;
        if key
            .get("kty")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
            || PRIVATE_JWK_MEMBERS
                .iter()
                .any(|member| key.contains_key(*member))
        {
            return Err(DidWebError::new(
                DidWebErrorReason::InvalidVerificationMethod,
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
        if !method_ids.contains(reference) {
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
        validate_absolute_did_url(id, true)?;
        if !did_url_belongs_to(id, did) {
            return Err(DidWebError::new(
                DidWebErrorReason::DocumentIdentifierMismatch,
            ));
        }
        if !resource_ids.insert(id.to_owned())
            || !object.contains_key("type")
            || !object.contains_key("serviceEndpoint")
        {
            return Err(DidWebError::new(DidWebErrorReason::InvalidService));
        }
    }
    Ok(())
}

/// Return true when an absolute DID URL's base DID is exactly `did`.
fn did_url_belongs_to(url: &str, did: &str) -> bool {
    url.strip_prefix(did)
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

fn zeroize_json(value: &mut Value) {
    match value {
        Value::String(value) => value.zeroize(),
        Value::Array(values) => {
            for value in values.iter_mut() {
                zeroize_json(value);
            }
            values.clear();
        }
        Value::Object(values) => {
            for value in values.values_mut() {
                zeroize_json(value);
            }
            values.clear();
        }
        Value::Number(_) => *value = Value::Null,
        Value::Bool(boolean) => *boolean = false,
        Value::Null => {}
    }
}
