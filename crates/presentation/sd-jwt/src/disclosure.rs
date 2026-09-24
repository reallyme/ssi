// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use serde::{Deserialize, Serialize};

/// Internal disclosure item (SD-JSON style).
///
/// This is NOT the SD-JWT wire format.
/// It is a reusable internal model.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
