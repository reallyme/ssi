// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use core::fmt;

use crate::KeySetError;
use reallyme_codec::multikey::parse_multikey;
use zeroize::{Zeroize, ZeroizeOnDrop};

const MAX_PUBLIC_KEY_MULTIBASE_BYTES: usize = 32 * 1024;

/// A validated `publicKeyMultibase` value.
///
/// ReallyMe public keys are multibase-encoded multikey values. Construction
/// decodes the multibase payload, validates the multicodec prefix is a known
/// public-key codec, and enforces the codec-specific public key length before
/// the string is allowed to flow into DID documents.
// Clone is deliberate because public keys are copied into immutable DID
// projections. Copies remain redacted and receive deterministic cleanup.
#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
pub struct PublicKeyMultibase(String);

impl fmt::Debug for PublicKeyMultibase {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PublicKeyMultibase([REDACTED])")
    }
}

impl Zeroize for PublicKeyMultibase {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl Drop for PublicKeyMultibase {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for PublicKeyMultibase {}

impl PublicKeyMultibase {
    /// Validate and construct a public key multibase value.
    pub fn new(value: impl Into<String>) -> Result<Self, KeySetError> {
        let value = value.into();

        if value.is_empty() || value.len() > MAX_PUBLIC_KEY_MULTIBASE_BYTES {
            return Err(KeySetError::InvalidPublicKeyMultibase);
        }

        parse_multikey(&value).map_err(|_| KeySetError::InvalidPublicKeyMultibase)?;

        Ok(Self(value))
    }

    /// Borrow the validated multibase string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consume the wrapper and return the validated multibase string.
    #[must_use]
    pub fn into_string(mut self) -> String {
        core::mem::take(&mut self.0)
    }
}
