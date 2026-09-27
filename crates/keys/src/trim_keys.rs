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
            let requested = VerificationMethodId::new(vm_id.clone())?;
            if self.private_keys.contains_key(&requested)
                || self.public_keys.contains_key(&requested)
            {
                keep.insert(requested);
                continue;
            }

            // DID documents commonly expose absolute verification-method IDs
            // while local key sets use fragments. Resolve that representation
            // difference before mutating either map so a valid absolute ID
            // cannot silently delete its local key material.
            let fragment = requested
                .as_str()
                .rsplit_once('#')
                .map(|(_, fragment)| fragment)
                .filter(|fragment| !fragment.is_empty())
                .ok_or(KeySetError::MissingPublicKey)?;
            let capacity = fragment
                .len()
                .checked_add(1)
                .ok_or(KeySetError::InvalidVerificationMethodId)?;
            let mut local_id = String::with_capacity(capacity);
            local_id.push('#');
            local_id.push_str(fragment);
            let local = VerificationMethodId::new(local_id)?;
            if !self.private_keys.contains_key(&local) && !self.public_keys.contains_key(&local) {
                return Err(KeySetError::MissingPublicKey);
            }
            keep.insert(local);
        }

        self.private_keys.retain(|id, _| keep.contains(id));
        self.public_keys.retain(|id, _| keep.contains(id));

        Ok(())
    }
}
