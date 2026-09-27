// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use zeroize::{Zeroize, ZeroizeOnDrop};

/// Verified disclosure output returned to a verifier.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct VerifiedDisclosure {
    /// Canonical claim path disclosed by the holder.
    claim_path: String,
    /// JCS-encoded disclosed claim value.
    value_jcs: Vec<u8>,
}

impl VerifiedDisclosure {
    /// Borrow the verified canonical claim path.
    #[must_use]
    pub fn claim_path(&self) -> &str {
        &self.claim_path
    }

    /// Borrow the verified JCS-encoded claim value.
    #[must_use]
    pub fn value_jcs(&self) -> &[u8] {
        &self.value_jcs
    }
}

impl core::fmt::Debug for VerifiedDisclosure {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("VerifiedDisclosure")
            .field("claim_path", &"<redacted>")
            .field("value_jcs", &"<redacted>")
            .finish()
    }
}
