// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use core::fmt;

use zeroize::{Zeroize, ZeroizeOnDrop};

/// Protocol-agnostic presentation binding and freshness input.
///
/// This captures the minimal semantic requirements shared across OpenID4VP,
/// web, QR, BLE, mdoc, and future delivery transports.
#[derive(Clone, PartialEq, Eq)]
pub struct PresentationBinding {
    /// Verifier challenge or nonce.
    pub nonce: [u8; 32],

    /// Hash of the intended verifier, audience, origin, or relying party.
    pub audience_hash: [u8; 32],

    /// Expiration time as Unix seconds.
    pub expiry_unix: u64,
}

impl fmt::Debug for PresentationBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PresentationBinding(<redacted>)")
    }
}

impl Zeroize for PresentationBinding {
    fn zeroize(&mut self) {
        self.nonce.zeroize();
        self.audience_hash.zeroize();
        self.expiry_unix.zeroize();
    }
}

impl Drop for PresentationBinding {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for PresentationBinding {}
