// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use zeroize::{Zeroize, ZeroizeOnDrop};

use super::X509Certificate;

/// Leaf-first certificate chain with an optional terminal trust anchor.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct X509Chain {
    /// Leaf first, followed by intermediates and an optional root.
    pub certs: Vec<X509Certificate>,
}

impl core::fmt::Debug for X509Chain {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("X509Chain")
            .field("certs", &"<redacted>")
            .finish()
    }
}

impl X509Chain {
    /// Returns the leaf certificate.
    pub fn leaf(&self) -> Option<&X509Certificate> {
        self.certs.first()
    }

    /// Iterates over certificates between the leaf and terminal trust anchor.
    pub fn intermediates(&self) -> impl Iterator<Item = &X509Certificate> {
        let intermediate_count = self.certs.len().saturating_sub(2);
        self.certs.iter().skip(1).take(intermediate_count)
    }

    /// Return the terminal trust anchor when the chain contains one.
    pub fn trust_anchor(&self) -> Option<&X509Certificate> {
        self.certs.last()
    }
}
