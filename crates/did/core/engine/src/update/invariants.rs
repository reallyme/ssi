// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::update::error::UpdateError;

/// Validate DID update chain invariants.
///
/// Rules:
/// - Genesis: (0 → 1) with no prev
/// - Update: (n → n+1) with prev == old_cid
pub fn validate_chain(
    old_seq: u64,
    new_seq: u64,
    old_cid: &str,
    prev: Option<&str>,
) -> Result<(), UpdateError> {
    // --- Genesis ---
    if old_seq == 0 && new_seq == 1 {
        if prev.is_none() {
            return Ok(());
        } else {
            return Err(UpdateError::InvalidPrev);
        }
    }

    // --- Normal update ---
    let Some(expected_next_seq) = old_seq.checked_add(1) else {
        return Err(UpdateError::InvalidSequence);
    };

    if new_seq != expected_next_seq {
        return Err(UpdateError::InvalidSequence);
    }

    match prev {
        Some(p) if p == old_cid => Ok(()),
        _ => Err(UpdateError::InvalidPrev),
    }
}
