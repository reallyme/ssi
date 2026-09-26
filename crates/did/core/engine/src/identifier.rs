// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::error::DidCoreError;

/// Domain-separation tag for signatures over canonical core bytes.
pub const CORE_SIGNATURE_DOMAIN_TAG: &[u8] = b"did:me:v1:core";

/// Build the byte string signed by core attestation keys.
pub fn core_signature_input(core_bytes: &[u8]) -> Result<Vec<u8>, DidCoreError> {
    let capacity = CORE_SIGNATURE_DOMAIN_TAG
        .len()
        .checked_add(core_bytes.len())
        .ok_or(DidCoreError::InternalInvariant)?;
    let mut input = Vec::with_capacity(capacity);
    input.extend_from_slice(CORE_SIGNATURE_DOMAIN_TAG);
    input.extend_from_slice(core_bytes);
    Ok(input)
}
