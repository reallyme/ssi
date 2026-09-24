// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use core::fmt;

use crate::KeySetError;
use zeroize::{Zeroize, ZeroizeOnDrop};

const MAX_VERIFICATION_METHOD_ID_BYTES: usize = 1024;

/// A validated DID verification method identifier.
///
/// The value may be a DID URL or a fragment identifier during document
/// construction. Validation is intentionally syntax-light here; DID-method
/// specific checks belong at the DID boundary, while this crate enforces the
/// security properties it needs: present, bounded, and log-safe.
// Clone is deliberate because identifiers are ordered map keys during atomic
// key-set filtering. Every clone has the same zeroizing destructor.
#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
pub struct VerificationMethodId(String);

impl fmt::Debug for VerificationMethodId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("VerificationMethodId([REDACTED])")
    }
}

impl Zeroize for VerificationMethodId {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl Drop for VerificationMethodId {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for VerificationMethodId {}

impl VerificationMethodId {
    /// Validate and construct a verification method id.
    pub fn new(value: impl Into<String>) -> Result<Self, KeySetError> {
        let value = value.into();

        if value.is_empty()
            || value.len() > MAX_VERIFICATION_METHOD_ID_BYTES
            || value.chars().any(is_log_unsafe_char)
        {
            return Err(KeySetError::InvalidVerificationMethodId);
        }

        Ok(Self(value))
    }

    /// Borrow the validated verification method identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consume the wrapper and return the validated identifier string.
    #[must_use]
    pub fn into_string(mut self) -> String {
        core::mem::take(&mut self.0)
    }
}

fn is_log_unsafe_char(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            '\u{061C}'
                | '\u{200B}'..='\u{200F}'
                | '\u{202A}'..='\u{202E}'
                | '\u{2066}'..='\u{2069}'
                | '\u{FEFF}'
        )
}
