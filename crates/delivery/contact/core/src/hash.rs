// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_crypto::sha2::digest as sha2_256_digest;

use crate::ContactDeliveryError;

/// Compute SHA-256 over a single byte slice.
pub fn sha256_bytes(data: &[u8]) -> [u8; 32] {
    sha2_256_digest(data).into_bytes()
}

/// Compute SHA-256 over three slices using the shared crypto owner.
pub fn sha256_concat(a: &[u8], b: &[u8], c: &[u8]) -> Result<[u8; 32], ContactDeliveryError> {
    let capacity = a
        .len()
        .checked_add(b.len())
        .and_then(|value| value.checked_add(c.len()))
        .ok_or(ContactDeliveryError::InvalidInput)?;
    let mut input = Vec::with_capacity(capacity);
    input.extend_from_slice(a);
    input.extend_from_slice(b);
    input.extend_from_slice(c);
    Ok(sha2_256_digest(&input).into_bytes())
}
