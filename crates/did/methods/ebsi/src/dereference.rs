// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Pure local did:ebsi DID URL dereferencing.

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{DidEbsiDocument, DidEbsiError, DidEbsiErrorReason};

/// Resource class selected from a validated EBSI document.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DidEbsiDereferenceKind {
    /// The complete registry document.
    Document,
    /// A verification method or service selected by absolute fragment URL.
    Fragment,
}

/// Deterministic JSON resource selected by local dereferencing.
pub struct DidEbsiDereferenceResult {
    /// Selected resource class.
    pub kind: DidEbsiDereferenceKind,
    encoded: Vec<u8>,
}

impl DidEbsiDereferenceResult {
    /// Borrow the selected JSON bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.encoded
    }
}

impl core::fmt::Debug for DidEbsiDereferenceResult {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("DidEbsiDereferenceResult(<redacted>)")
    }
}

impl Zeroize for DidEbsiDereferenceResult {
    fn zeroize(&mut self) {
        self.encoded.zeroize();
        self.encoded.clear();
    }
}

impl Drop for DidEbsiDereferenceResult {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for DidEbsiDereferenceResult {}

/// Select the full document or an absolute fragment resource without I/O.
pub fn dereference_did_ebsi_document(
    document: &DidEbsiDocument,
    did_url: &str,
) -> Result<DidEbsiDereferenceResult, DidEbsiError> {
    let did = document
        .id()
        .ok_or(DidEbsiError::new(DidEbsiErrorReason::InvalidDocument))?;
    if did_url == did {
        return Ok(DidEbsiDereferenceResult {
            kind: DidEbsiDereferenceKind::Document,
            encoded: document.as_bytes().to_vec(),
        });
    }
    let fragment = did_url
        .strip_prefix(did)
        .and_then(|suffix| suffix.strip_prefix('#'))
        .filter(|fragment| valid_fragment(fragment))
        .ok_or(DidEbsiError::new(DidEbsiErrorReason::InvalidDidUrl))?;
    let expected_len = did
        .len()
        .checked_add(1)
        .and_then(|length| length.checked_add(fragment.len()))
        .ok_or(DidEbsiError::new(DidEbsiErrorReason::ArithmeticOverflow))?;
    if did_url.len() != expected_len {
        return Err(DidEbsiError::new(DidEbsiErrorReason::InvalidDidUrl));
    }
    let resource = document
        .verification_method(did_url)
        .or_else(|| document.service(did_url))
        .ok_or(DidEbsiError::new(DidEbsiErrorReason::InvalidDidUrl))?;
    let encoded = serde_json::to_vec(resource)
        .map_err(|_| DidEbsiError::new(DidEbsiErrorReason::InvalidDocument))?;
    Ok(DidEbsiDereferenceResult {
        kind: DidEbsiDereferenceKind::Fragment,
        encoded,
    })
}

fn valid_fragment(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~' | b':' | b'@')
        })
}

#[cfg(test)]
#[path = "dereference_tests.rs"]
mod tests;
