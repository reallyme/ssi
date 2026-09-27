// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Pure validation for legal-entity did:ebsi registry documents.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Map, Value};
use url::Url;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::did_url::validate_absolute_did_url;
use crate::jwk::validate_public_jwk;
use crate::jwk::EbsiJwkPurposes;
use crate::{parse_did_ebsi, DidEbsiError, DidEbsiErrorReason};

mod validate_service;

use validate_service::validate_services;

const DID_CORE_CONTEXT: &str = "https://www.w3.org/ns/did/v1";
const LEGACY_EBSI_DID_CONTEXT: &str = "https://w3id.org/did/v1";
const RELATIONSHIPS: [&str; 5] = [
    "authentication",
    "assertionMethod",
    "keyAgreement",
    "capabilityInvocation",
    "capabilityDelegation",
];
/// Lifecycle state expected from an EBSI registry document.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DidEbsiDocumentState {
    /// An active legal-entity document with usable registry invocation authority.
    Active,
    /// An immutable or effectively inactive historical registry document.
    EffectivelyDeactivated,
}

/// Resource bounds applied before an EBSI registry response is adopted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DidEbsiDocumentLimits {
    /// Maximum encoded JSON size.
    pub max_bytes: usize,
    /// Maximum JSON container nesting depth.
    pub max_depth: usize,
    /// Maximum total JSON values.
    pub max_nodes: usize,
}

impl Default for DidEbsiDocumentLimits {
    fn default() -> Self {
        Self {
            max_bytes: 1024 * 1024,
            max_depth: 32,
            max_nodes: 4096,
        }
    }
}

/// Validated EBSI legal-entity DID document with deterministic cleanup.
pub struct DidEbsiDocument {
    pub(crate) value: Value,
    encoded: Vec<u8>,
}

impl DidEbsiDocument {
    /// Borrow the validated document identifier.
    #[must_use]
    pub fn id(&self) -> Option<&str> {
        self.value.get("id").and_then(Value::as_str)
    }

    /// Borrow the exact bounded JSON received from the registry provider.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.encoded
    }

    /// Return whether the document contains the exact verification method id.
    #[must_use]
    pub fn has_verification_method(&self, identifier: &str) -> bool {
        self.verification_method(identifier).is_some()
    }

    /// Return whether the active update-authority relationship contains the id.
    #[must_use]
    pub fn capability_invocation_contains(&self, identifier: &str) -> bool {
        relationship_identifiers(&self.value, "capabilityInvocation")
            .is_some_and(|values| values.contains(&identifier))
    }

    /// Return whether the document has no controller or no invocation key and
    /// therefore cannot perform another registry write through its own authority.
    #[must_use]
    pub fn is_effectively_deactivated(&self) -> bool {
        controller_values(&self.value).is_none_or(|values| values.is_empty())
            || relationship_identifiers(&self.value, "capabilityInvocation")
                .is_none_or(|values| values.is_empty())
    }

    pub(crate) fn verification_method(&self, identifier: &str) -> Option<&Map<String, Value>> {
        self.value
            .get("verificationMethod")
            .and_then(Value::as_array)
            .and_then(|values| {
                values.iter().find_map(|value| {
                    value.as_object().filter(|method| {
                        method.get("id").and_then(Value::as_str) == Some(identifier)
                    })
                })
            })
    }

    pub(crate) fn service(&self, identifier: &str) -> Option<&Map<String, Value>> {
        self.value
            .get("service")
            .and_then(Value::as_array)
            .and_then(|values| {
                values.iter().find_map(|value| {
                    value.as_object().filter(|service| {
                        service.get("id").and_then(Value::as_str) == Some(identifier)
                    })
                })
            })
    }
}

impl core::fmt::Debug for DidEbsiDocument {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("DidEbsiDocument(<redacted>)")
    }
}

impl Zeroize for DidEbsiDocument {
    fn zeroize(&mut self) {
        zeroize_json(&mut self.value);
        self.encoded.zeroize();
        self.encoded.clear();
    }
}

impl Drop for DidEbsiDocument {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for DidEbsiDocument {}

/// Parse and validate an EBSI registry document for the requested identifier.
pub fn parse_and_validate_did_ebsi_document(
    requested_did: &str,
    bytes: &[u8],
    limits: DidEbsiDocumentLimits,
) -> Result<DidEbsiDocument, DidEbsiError> {
    parse_and_validate_did_ebsi_document_for_state(
        requested_did,
        bytes,
        limits,
        DidEbsiDocumentState::Active,
    )
}

/// Parse and validate a registry document in an explicit lifecycle state.
pub fn parse_and_validate_did_ebsi_document_for_state(
    requested_did: &str,
    bytes: &[u8],
    limits: DidEbsiDocumentLimits,
    state: DidEbsiDocumentState,
) -> Result<DidEbsiDocument, DidEbsiError> {
    parse_did_ebsi(requested_did)?;
    if bytes.is_empty() || bytes.len() > limits.max_bytes {
        return Err(DidEbsiError::new(DidEbsiErrorReason::DocumentLimitExceeded));
    }
    identity_core_primitives::validate_json::validate_json(bytes)
        .map_err(|_| DidEbsiError::new(DidEbsiErrorReason::InvalidDocument))?;
    let value: Value = serde_json::from_slice(bytes)
        .map_err(|_| DidEbsiError::new(DidEbsiErrorReason::InvalidDocument))?;
    validate_shape_limits(&value, limits)?;
    validate_document(requested_did, &value, state)?;
    Ok(DidEbsiDocument {
        value,
        encoded: bytes.to_vec(),
    })
}

fn validate_shape_limits(value: &Value, limits: DidEbsiDocumentLimits) -> Result<(), DidEbsiError> {
    let mut stack = vec![(value, 1usize)];
    let mut nodes = 0usize;
    while let Some((current, depth)) = stack.pop() {
        nodes = nodes
            .checked_add(1)
            .ok_or(DidEbsiError::new(DidEbsiErrorReason::DocumentLimitExceeded))?;
        if nodes > limits.max_nodes || depth > limits.max_depth {
            return Err(DidEbsiError::new(DidEbsiErrorReason::DocumentLimitExceeded));
        }
        let next_depth = depth
            .checked_add(1)
            .ok_or(DidEbsiError::new(DidEbsiErrorReason::DocumentLimitExceeded))?;
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

fn validate_document(
    requested_did: &str,
    value: &Value,
    state: DidEbsiDocumentState,
) -> Result<(), DidEbsiError> {
    let object = value
        .as_object()
        .ok_or(DidEbsiError::new(DidEbsiErrorReason::InvalidDocument))?;
    if object.get("id").and_then(Value::as_str) != Some(requested_did) {
        return Err(DidEbsiError::new(
            DidEbsiErrorReason::DocumentIdentifierMismatch,
        ));
    }
    validate_context(object)?;
    validate_also_known_as(object)?;
    let controllers = validate_controllers(object, state)?;
    let controller_count = controllers.len();
    let mut methods = validate_verification_methods(requested_did, object, &controllers)?;
    validate_services(object)?;
    validate_relationships(requested_did, object, &controllers, &mut methods, state)?;
    let invocation_count =
        relationship_identifiers(value, "capabilityInvocation").map_or(0, |values| values.len());
    match state {
        DidEbsiDocumentState::Active if controller_count > 0 && invocation_count > 0 => Ok(()),
        DidEbsiDocumentState::Active => Err(DidEbsiError::new(DidEbsiErrorReason::InvalidDocument)),
        DidEbsiDocumentState::EffectivelyDeactivated
            if controller_count == 0 || invocation_count == 0 =>
        {
            Ok(())
        }
        DidEbsiDocumentState::EffectivelyDeactivated => {
            Err(DidEbsiError::new(DidEbsiErrorReason::InvalidDocument))
        }
    }
}

fn validate_also_known_as(object: &Map<String, Value>) -> Result<(), DidEbsiError> {
    let Some(values) = object.get("alsoKnownAs") else {
        return Ok(());
    };
    let values = values
        .as_array()
        .filter(|values| !values.is_empty())
        .ok_or(DidEbsiError::new(DidEbsiErrorReason::InvalidDocument))?;
    let mut unique = BTreeSet::new();
    for value in values {
        let value = value
            .as_str()
            .filter(|value| !value.is_empty())
            .ok_or(DidEbsiError::new(DidEbsiErrorReason::InvalidDocument))?;
        if Url::parse(value).is_err() || !unique.insert(value) {
            return Err(DidEbsiError::new(DidEbsiErrorReason::InvalidDocument));
        }
    }
    Ok(())
}

fn validate_context(object: &Map<String, Value>) -> Result<(), DidEbsiError> {
    let valid = match object.get("@context") {
        Some(Value::String(value)) => context_is_supported(value),
        Some(Value::Array(values)) => {
            values
                .first()
                .and_then(Value::as_str)
                .is_some_and(context_is_supported)
                && values
                    .iter()
                    .skip(1)
                    .all(|value| matches!(value, Value::String(_) | Value::Object(_)))
        }
        _ => false,
    };
    if valid {
        Ok(())
    } else {
        Err(DidEbsiError::new(DidEbsiErrorReason::InvalidDocument))
    }
}

fn context_is_supported(value: &str) -> bool {
    matches!(value, DID_CORE_CONTEXT | LEGACY_EBSI_DID_CONTEXT)
}

fn validate_controllers(
    object: &Map<String, Value>,
    state: DidEbsiDocumentState,
) -> Result<BTreeSet<&str>, DidEbsiError> {
    let mut controllers = BTreeSet::new();
    match object.get("controller") {
        Some(Value::String(value)) if valid_controller(value) => {
            controllers.insert(value.as_str());
        }
        Some(Value::Array(values)) if !values.is_empty() => {
            for value in values {
                let controller = value
                    .as_str()
                    .filter(|controller| valid_controller(controller))
                    .ok_or(DidEbsiError::new(DidEbsiErrorReason::InvalidDocument))?;
                if !controllers.insert(controller) {
                    return Err(DidEbsiError::new(DidEbsiErrorReason::InvalidDocument));
                }
            }
        }
        Some(Value::Array(values))
            if values.is_empty() && state == DidEbsiDocumentState::EffectivelyDeactivated => {}
        None => {}
        _ => return Err(DidEbsiError::new(DidEbsiErrorReason::InvalidDocument)),
    }
    Ok(controllers)
}

fn valid_controller(value: &str) -> bool {
    parse_did_ebsi(value).is_ok()
}

fn validate_verification_methods<'a>(
    requested_did: &str,
    object: &'a Map<String, Value>,
    controllers: &BTreeSet<&str>,
) -> Result<BTreeMap<&'a str, EbsiJwkPurposes>, DidEbsiError> {
    let values = match object.get("verificationMethod") {
        Some(Value::Array(values)) => values,
        None => return Ok(BTreeMap::new()),
        _ => return Err(DidEbsiError::new(DidEbsiErrorReason::InvalidDocument)),
    };
    let mut methods = BTreeMap::new();
    for value in values {
        let method = value
            .as_object()
            .ok_or(DidEbsiError::new(DidEbsiErrorReason::InvalidDocument))?;
        let (identifier, purposes) =
            validate_verification_method(requested_did, controllers, method)?;
        if methods.insert(identifier, purposes).is_some() {
            return Err(DidEbsiError::new(DidEbsiErrorReason::InvalidDocument));
        }
    }
    Ok(methods)
}

fn validate_verification_method<'a>(
    requested_did: &str,
    controllers: &BTreeSet<&str>,
    method: &'a Map<String, Value>,
) -> Result<(&'a str, EbsiJwkPurposes), DidEbsiError> {
    let identifier = required_string(method, "id")?;
    validate_absolute_did_url(identifier)?;
    let controller = required_string(method, "controller")?;
    if !valid_local_verification_method_id(identifier, requested_did)
        || !valid_controller(controller)
        || (controller != requested_did && !controllers.contains(controller))
        || method.get("type").and_then(Value::as_str) != Some("JsonWebKey2020")
    {
        return Err(DidEbsiError::new(DidEbsiErrorReason::InvalidDocument));
    }
    let purposes = validate_public_jwk(method.get("publicKeyJwk"), identifier)?;
    Ok((identifier, purposes))
}

fn validate_relationships<'a>(
    requested_did: &str,
    object: &'a Map<String, Value>,
    controllers: &BTreeSet<&str>,
    methods: &mut BTreeMap<&'a str, EbsiJwkPurposes>,
    state: DidEbsiDocumentState,
) -> Result<(), DidEbsiError> {
    for name in RELATIONSHIPS {
        let Some(values) = object.get(name) else {
            continue;
        };
        let values = values
            .as_array()
            .ok_or(DidEbsiError::new(DidEbsiErrorReason::InvalidDocument))?;
        if values.is_empty() {
            if state == DidEbsiDocumentState::EffectivelyDeactivated {
                continue;
            }
            return Err(DidEbsiError::new(DidEbsiErrorReason::InvalidDocument));
        }
        let mut relationship_ids = BTreeSet::new();
        for value in values {
            let (identifier, purposes) = match value {
                Value::String(reference) => {
                    validate_absolute_did_url(reference)?;
                    let purposes = *methods
                        .get(reference.as_str())
                        .ok_or(DidEbsiError::new(DidEbsiErrorReason::InvalidDocument))?;
                    (reference.as_str(), Some(purposes))
                }
                Value::Object(method) => {
                    let (identifier, purposes) =
                        validate_verification_method(requested_did, controllers, method)?;
                    if methods.insert(identifier, purposes).is_some() {
                        return Err(DidEbsiError::new(DidEbsiErrorReason::InvalidDocument));
                    }
                    (identifier, Some(purposes))
                }
                _ => return Err(DidEbsiError::new(DidEbsiErrorReason::InvalidDocument)),
            };
            if !relationship_ids.insert(identifier)
                || purposes.is_some_and(|purposes| !purpose_allowed(name, purposes))
            {
                return Err(DidEbsiError::new(DidEbsiErrorReason::InvalidDocument));
            }
        }
    }
    Ok(())
}

fn purpose_allowed(name: &str, purposes: EbsiJwkPurposes) -> bool {
    if name == "keyAgreement" {
        purposes.key_agreement
    } else {
        purposes.signature
    }
}

fn valid_local_verification_method_id(value: &str, did: &str) -> bool {
    value
        .strip_prefix(did)
        .and_then(|suffix| suffix.strip_prefix('#'))
        .is_some_and(|fragment| !fragment.is_empty())
}

fn controller_values(value: &Value) -> Option<Vec<&str>> {
    match value.get("controller")? {
        Value::String(controller) => Some(vec![controller.as_str()]),
        Value::Array(values) => values.iter().map(Value::as_str).collect(),
        _ => None,
    }
}

fn relationship_identifiers<'a>(value: &'a Value, name: &str) -> Option<Vec<&'a str>> {
    value
        .get(name)?
        .as_array()?
        .iter()
        .map(|entry| match entry {
            Value::String(identifier) => Some(identifier.as_str()),
            Value::Object(method) => method.get("id").and_then(Value::as_str),
            _ => None,
        })
        .collect()
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

fn zeroize_json(value: &mut Value) {
    match value {
        Value::String(text) => text.zeroize(),
        Value::Array(values) => values.iter_mut().for_each(zeroize_json),
        Value::Object(values) => values.values_mut().for_each(zeroize_json),
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

#[cfg(test)]
#[path = "document_tests.rs"]
mod tests;
