// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::fmt;

use secrecy::{ExposeSecret, SecretBox};
use zeroize::Zeroizing;

use crate::KeySetError;

const MAX_PRIVATE_KEY_BYTES: usize = 16 * 1024;

/// Private key bytes held in a zeroizing allocation.
///
/// The type deliberately exposes borrowed access for signing/import pipelines
/// and requires an explicit method call to produce an owned copy. That makes
/// secret duplication visible at call sites while still supporting existing
/// workflows that need to hand key bytes to crypto adapters.
pub struct PrivateKeyMaterial {
    bytes: SecretBox<Zeroizing<Vec<u8>>>,
}

impl PrivateKeyMaterial {
    /// Validate and wrap private key material.
    ///
    /// Empty or unexpectedly large inputs are rejected before they can enter the
    /// key set. The size limit is intentionally generous for modern key formats
    /// while still bounding memory use for malicious imports.
    pub fn new(bytes: Vec<u8>) -> Result<Self, KeySetError> {
        Self::new_zeroizing(Zeroizing::new(bytes))
    }

    /// Validate and take ownership of already-zeroizing private key material.
    ///
    /// This path preserves the owner returned by cryptographic key generation,
    /// including when validation fails before the key reaches storage.
    pub fn new_zeroizing(bytes: Zeroizing<Vec<u8>>) -> Result<Self, KeySetError> {
        if bytes.is_empty() || bytes.len() > MAX_PRIVATE_KEY_BYTES {
            return Err(KeySetError::InvalidPrivateKeyMaterial);
        }

        Ok(Self {
            bytes: SecretBox::new(Box::new(bytes)),
        })
    }

    /// Borrow the private bytes for immediate cryptographic use.
    #[must_use]
    pub fn expose_secret(&self) -> &[u8] {
        self.bytes.expose_secret().as_slice()
    }

    /// Return an explicitly owned, zeroizing copy for cryptographic APIs that
    /// cannot consume a borrowed key.
    ///
    /// Prefer `expose_secret` where possible so private material is not copied
    /// beyond the zeroizing storage boundary.
    #[must_use]
    pub fn to_vec(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(self.bytes.expose_secret().to_vec())
    }
}

impl PrivateKeyMaterial {
    /// Produce an independent zeroizing copy.
    ///
    /// Deliberately not exposed as `Clone`: duplicating secret material is
    /// confined to explicit, crate-internal snapshot operations.
    pub(crate) fn duplicate(&self) -> Self {
        Self {
            bytes: SecretBox::new(Box::new(Zeroizing::new(
                self.bytes.expose_secret().to_vec(),
            ))),
        }
    }
}

impl fmt::Debug for PrivateKeyMaterial {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateKeyMaterial")
            .field("len", &self.bytes.expose_secret().len())
            .field("bytes", &"<redacted>")
            .finish()
    }
}
