// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Zeroizing ownership for converted did:me domain documents.

use core::fmt;

use reallyme_did_types::DIDDocument;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Non-cloneable owner for a converted DID document containing identifying,
/// key, proof, device, and domain material.
pub struct SensitiveDidDocument {
    inner: DIDDocument,
}

impl SensitiveDidDocument {
    pub(crate) fn from_document(inner: DIDDocument) -> Self {
        Self { inner }
    }

    /// Borrow the converted domain document for validation.
    #[must_use]
    pub fn as_document(&self) -> &DIDDocument {
        &self.inner
    }
}

impl fmt::Debug for SensitiveDidDocument {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SensitiveDidDocument(<redacted>)")
    }
}

impl Zeroize for SensitiveDidDocument {
    fn zeroize(&mut self) {
        self.inner.zeroize();
    }
}

impl Drop for SensitiveDidDocument {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for SensitiveDidDocument {}

#[cfg(test)]
#[path = "sensitive_document_tests.rs"]
mod tests;
