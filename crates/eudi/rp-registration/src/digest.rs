// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use serde::Serialize;
use zeroize::Zeroize;

/// SHA-256 digest binding an authenticated or prepared artifact to exact bytes.
#[derive(Clone, Copy, Eq, Hash, PartialEq, Serialize, Zeroize)]
pub struct ArtifactDigest([u8; 32]);

impl ArtifactDigest {
    pub(crate) fn of(bytes: &[u8]) -> Self {
        Self(reallyme_crypto::sha2::digest(bytes).into_bytes())
    }

    /// Computes the canonical SHA-256 artifact digest used by this profile.
    #[must_use]
    pub fn sha256(bytes: &[u8]) -> Self {
        Self::of(bytes)
    }

    /// Constructs a digest received from a trusted storage boundary.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the fixed-size digest.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl core::fmt::Debug for ArtifactDigest {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ArtifactDigest(<redacted>)")
    }
}
