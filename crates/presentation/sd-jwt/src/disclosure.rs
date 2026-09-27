// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Internal disclosure item (SD-JSON style).
///
/// This is NOT the SD-JWT wire format.
/// It is a reusable internal model.
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct DisclosureItem {
    /// Canonical claim path disclosed by this item.
    pub claim_path: String,

    /// JCS bytes of the value
    pub value: Vec<u8>,

    /// Random salt used in commitment
    pub salt: Vec<u8>,

    /// Merkle path (bottom-up)
    pub merkle_path: Vec<Vec<u8>>,
}

impl core::fmt::Debug for DisclosureItem {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("DisclosureItem")
            .field("claim_path", &"<redacted>")
            .field("value", &"<redacted>")
            .field("salt", &"<redacted>")
            .field("merkle_path", &"<redacted>")
            .finish()
    }
}
