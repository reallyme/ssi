// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::KeySet;

impl KeySet {
    /// Deep-copy all keys into another key set.
    ///
    /// The target is cleared first so callers get an exact snapshot. Cloning
    /// private material is intentionally centralized here rather than hidden
    /// behind a blanket `Clone` implementation for `KeySet`.
    pub fn copy_into(&self, target: &mut KeySet) {
        target.private_keys.clear();
        target.public_keys.clear();

        target.private_keys = self.private_keys.clone();
        target.public_keys = self.public_keys.clone();
    }
}
