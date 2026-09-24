// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::update::error::UpdateError;
use reallyme_did_types::VerificationMethod;
use std::collections::HashMap;

/// Apply public-key rotations to verification methods.
///
/// Invariants (TS parity):
/// - Only VMs explicitly marked `true` are rotated
/// - Rotated VM MUST exist
/// - Rotated VM MUST have new publicKeyMultibase
/// - VM count and order are preserved
pub fn apply_rotations(
    old_vms: &[VerificationMethod],
    rotate: &HashMap<String, bool>,
    key_lookup: impl Fn(&str) -> Option<String>,
) -> Result<Vec<VerificationMethod>, UpdateError> {
    // 1. Validate rotation map refers only to existing VMs
    for (vm_id, do_rotate) in rotate {
        if *do_rotate && !old_vms.iter().any(|vm| vm.id == *vm_id) {
            return Err(UpdateError::UnknownVerificationMethod);
        }
    }

    // 2. Apply rotations
    let mut out = Vec::with_capacity(old_vms.len());

    for vm in old_vms {
        let mut vm2 = vm.clone();

        if rotate.get(&vm.id) == Some(&true) {
            let new_pub = key_lookup(&vm.id).ok_or(UpdateError::MissingRotatedKey)?;

            vm2.public_key_multibase = new_pub;
        }

        out.push(vm2);
    }

    Ok(out)
}
