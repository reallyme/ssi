// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Pure did:web DID-document parsing and validation.

use serde_json::Value;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{DidWebError, DidWebErrorReason, DidWebJsonLdError};
use crate::method::DidWebIdentifier;

mod validate;

use validate::{validate_document, validate_shape_limits};
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

/// Injected JSON-LD processing boundary for documents carrying `@context`.
///
/// Implementations must perform JSON-LD processing with an authenticated,
/// bounded context loader and reject expansion or DID data-model conversion
/// failures. Keeping context retrieval outside this crate prevents hidden
/// network access and lets applications pin the contexts they trust.
pub trait DidWebJsonLdProcessor {
    /// Process and validate one already bounded, duplicate-free JSON document.
    fn validate_json_ld(&self, document_json: &[u8]) -> Result<(), DidWebJsonLdError>;
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
    parse_and_validate_document(requested, bytes, limits, None)
}

/// Parse and validate a bounded did:web JSON-LD document.
///
/// The processor is invoked whenever the root object carries `@context`.
pub fn parse_and_validate_did_web_document_with_json_ld_processor(
    requested: &DidWebIdentifier,
    bytes: &[u8],
    limits: DidWebDocumentLimits,
    processor: &dyn DidWebJsonLdProcessor,
) -> Result<DidWebDocument, DidWebError> {
    parse_and_validate_document(requested, bytes, limits, Some(processor))
}

fn parse_and_validate_document(
    requested: &DidWebIdentifier,
    bytes: &[u8],
    limits: DidWebDocumentLimits,
    processor: Option<&dyn DidWebJsonLdProcessor>,
) -> Result<DidWebDocument, DidWebError> {
    if bytes.is_empty() || bytes.len() > limits.max_bytes {
        return Err(DidWebError::new(DidWebErrorReason::ResponseTooLarge));
    }
    identity_core_primitives::validate_json::validate_json(bytes)
        .map_err(|_| DidWebError::new(DidWebErrorReason::InvalidDocument))?;
    let value: Value = serde_json::from_slice(bytes)
        .map_err(|_| DidWebError::new(DidWebErrorReason::InvalidDocument))?;
    validate_shape_limits(&value, limits)?;
    if value
        .as_object()
        .is_some_and(|object| object.contains_key("@context"))
    {
        let processor = processor.ok_or(DidWebError::new(
            DidWebErrorReason::JsonLdProcessorUnavailable,
        ))?;
        processor
            .validate_json_ld(bytes)
            .map_err(|_| DidWebError::new(DidWebErrorReason::InvalidJsonLd))?;
    }
    validate_document(requested, &value)?;
    Ok(DidWebDocument {
        value,
        encoded: bytes.to_vec(),
    })
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
