// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

/// Domain-separation tag for signatures over canonical core bytes.
pub const CORE_SIGNATURE_DOMAIN_TAG: &[u8] = b"did:me:v1:core";

/// Build the byte string signed by core attestation keys.
pub fn core_signature_input(core_bytes: &[u8]) -> Vec<u8> {
    let mut input = Vec::with_capacity(CORE_SIGNATURE_DOMAIN_TAG.len() + core_bytes.len());
    input.extend_from_slice(CORE_SIGNATURE_DOMAIN_TAG);
    input.extend_from_slice(core_bytes);
    input
}
