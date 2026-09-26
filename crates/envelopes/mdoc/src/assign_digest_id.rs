// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::MdocEnvelopeError;
use reallyme_crypto::csprng::{generate_bytes, SecureRandom};
use std::collections::BTreeSet;

const MAX_COLLISION_ATTEMPTS: usize = 16;
const DIGEST_ID_BYTES: usize = 8;
// The shared CBOR model represents positive integers through i64.
const MAX_DIGEST_ID: u64 = 0x7fff_ffff_ffff_ffff;

pub(crate) fn assign_digest_id(
    used: &mut BTreeSet<u64>,
    random: &mut impl SecureRandom,
) -> Result<u64, MdocEnvelopeError> {
    for _ in 0..MAX_COLLISION_ATTEMPTS {
        let bytes = generate_bytes::<DIGEST_ID_BYTES>(
            random,
            reallyme_crypto::core::RngOutputKind::Generic,
        )
        .map_err(|_| MdocEnvelopeError::RandomnessUnavailable)?;
        let id = u64::from_be_bytes(*bytes.as_bytes()) & MAX_DIGEST_ID;
        if used.insert(id) {
            return Ok(id);
        }
    }
    // A faulty injected provider must not turn collisions into an infinite loop.
    Err(MdocEnvelopeError::RandomnessUnavailable)
}

#[cfg(test)]
#[path = "assign_digest_id_tests.rs"]
mod tests;
