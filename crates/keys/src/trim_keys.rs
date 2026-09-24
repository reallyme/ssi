// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::collections::BTreeSet;

use crate::{KeySet, KeySetError, VerificationMethodId};

impl KeySet {
    /// Trim keys to only the listed verification method IDs.
    pub fn trim_to_vms(&mut self, vm_ids: &[String]) -> Result<(), KeySetError> {
        let mut keep = BTreeSet::new();

        for vm_id in vm_ids {
            keep.insert(VerificationMethodId::new(vm_id.clone())?);
        }

        self.private_keys.retain(|id, _| keep.contains(id));
        self.public_keys.retain(|id, _| keep.contains(id));

        Ok(())
    }
}
