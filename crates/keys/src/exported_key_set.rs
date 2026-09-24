// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Base64-encoded private key material for JSON import/export.
///
/// This wrapper preserves the external JSON shape as a string while keeping the
/// in-memory export value redacted in debug output and zeroized on drop.
pub struct ExportedPrivateKey {
    encoded: Zeroizing<String>,
}

impl ExportedPrivateKey {
    /// Wrap an encoded private key string.
    ///
    /// The caller is responsible for passing an already validated encoding;
    /// import validation happens when an `ExportedKeySet` is consumed.
    #[must_use]
    pub fn new(encoded: String) -> Self {
        Self {
            encoded: Zeroizing::new(encoded),
        }
    }

    /// Borrow the encoded private key string for serialization or import.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.encoded.as_str()
    }
}

impl fmt::Debug for ExportedPrivateKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("<redacted>")
    }
}

impl Serialize for ExportedPrivateKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for ExportedPrivateKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer).map(Self::new)
    }
}

/// JSON-compatible key-set representation.
///
/// Private values are base64-encoded secret key material. `Debug` is redacted so
/// accidental assertion or tracing output cannot leak the encoded private keys.
#[derive(Deserialize, Serialize)]
pub struct ExportedKeySet {
    /// Base64-encoded private key material keyed by verification method id.
    pub private: BTreeMap<String, ExportedPrivateKey>,

    /// Multibase/multikey public key material keyed by verification method id.
    pub public: BTreeMap<String, String>,
}

impl fmt::Debug for ExportedKeySet {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExportedKeySet")
            .field("private_key_count", &self.private.len())
            .field("public_key_count", &self.public.len())
            .finish()
    }
}

impl Zeroize for ExportedKeySet {
    fn zeroize(&mut self) {
        for (mut id, private_key) in core::mem::take(&mut self.private) {
            id.zeroize();
            drop(private_key);
        }
        for (mut id, mut public_key) in core::mem::take(&mut self.public) {
            id.zeroize();
            public_key.zeroize();
        }
    }
}

impl Drop for ExportedKeySet {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for ExportedKeySet {}
