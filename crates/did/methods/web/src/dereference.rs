// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Pure, local did:web DID URL dereferencing.

use serde_json::Value;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::did_url::validate_absolute_did_url;
use crate::document::DidWebDocument;
use crate::error::{DidWebError, DidWebErrorReason};

const RELATIONSHIPS: [&str; 5] = [
    "authentication",
    "assertionMethod",
    "keyAgreement",
    "capabilityInvocation",
    "capabilityDelegation",
];

/// Kind of local resource selected from a validated did:web document.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DidWebDereferenceKind {
    /// The complete DID document.
    Document,
    /// A verification method or service selected by an absolute fragment DID URL.
    Fragment,
}

/// Bounded JSON resource returned by pure did:web DID URL dereferencing.
pub struct DidWebDereferenceResult {
    /// Selected resource kind.
    pub kind: DidWebDereferenceKind,
    resource_json: Vec<u8>,
}

impl DidWebDereferenceResult {
    /// Borrow the serialized JSON resource.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.resource_json
    }
}

impl core::fmt::Debug for DidWebDereferenceResult {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("DidWebDereferenceResult(<redacted>)")
    }
}

impl Zeroize for DidWebDereferenceResult {
    fn zeroize(&mut self) {
        self.resource_json.zeroize();
        self.resource_json.clear();
    }
}

impl Drop for DidWebDereferenceResult {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for DidWebDereferenceResult {}

/// Select a document or fragment resource using an absolute canonical did:web DID URL.
pub fn dereference_did_web_document(
    document: &DidWebDocument,
    did_url: &str,
) -> Result<DidWebDereferenceResult, DidWebError> {
    validate_absolute_did_url(did_url, false)?;
    let suffix_index = did_url.find(['/', '?', '#']).unwrap_or(did_url.len());
    let base = &did_url[..suffix_index];
    if document.id() != Some(base) {
        return Err(DidWebError::new(
            DidWebErrorReason::DocumentIdentifierMismatch,
        ));
    }
    let suffix = &did_url[suffix_index..];
    if suffix.is_empty() {
        return Ok(DidWebDereferenceResult {
            kind: DidWebDereferenceKind::Document,
            resource_json: document.as_bytes().to_vec(),
        });
    }
    if !suffix.starts_with('#') || suffix.len() == 1 {
        return Err(DidWebError::new(DidWebErrorReason::InvalidDidUrl));
    }
    let resource = find_fragment_resource(document.as_json(), did_url).ok_or(DidWebError::new(
        DidWebErrorReason::UnresolvedRelationshipReference,
    ))?;
    let resource_json = serde_json::to_vec(resource)
        .map_err(|_| DidWebError::new(DidWebErrorReason::InvalidDocument))?;
    Ok(DidWebDereferenceResult {
        kind: DidWebDereferenceKind::Fragment,
        resource_json,
    })
}

fn find_fragment_resource<'a>(document: &'a Value, did_url: &str) -> Option<&'a Value> {
    let object = document.as_object()?;
    if let Some(resource) = find_by_id(object.get("verificationMethod"), did_url) {
        return Some(resource);
    }
    for relationship in RELATIONSHIPS {
        if let Some(resource) = find_by_id(object.get(relationship), did_url) {
            return Some(resource);
        }
    }
    find_by_id(object.get("service"), did_url)
}

fn find_by_id<'a>(values: Option<&'a Value>, did_url: &str) -> Option<&'a Value> {
    values?.as_array()?.iter().find(|value| {
        value
            .as_object()
            .and_then(|object| object.get("id"))
            .and_then(Value::as_str)
            == Some(did_url)
    })
}
