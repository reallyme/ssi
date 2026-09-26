// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Length policy for `IssuerSignedItem.random` salts.
//!
//! The randomizer is the only secret that prevents a verifier from confirming
//! guessed undisclosed element values against the MSO digests, so issuance
//! enforces the ISO/IEC 18013-5 minimum and a bounded maximum. Decoding
//! enforces the same minimum so under-salted items are never accepted.

use crate::{
    MdocEnvelopeError, MdocInvalidInputReason, MAX_MDOC_ITEM_RANDOM_BYTES,
    MIN_MDOC_ITEM_RANDOM_BYTES,
};

/// Validate a randomizer supplied for issuance.
pub(crate) fn validate_issuance_item_random(random: &[u8]) -> Result<(), MdocEnvelopeError> {
    validate_decoded_item_random(random)?;
    if random.len() > MAX_MDOC_ITEM_RANDOM_BYTES {
        return Err(MdocEnvelopeError::InvalidInput(
            MdocInvalidInputReason::InvalidRandomLength,
        ));
    }

    Ok(())
}

/// Validate a randomizer decoded from an issuer-signed item.
///
/// ISO/IEC 18013-5 defines no maximum randomizer length, so decoding only
/// enforces the minimum; overall size stays bounded by the CBOR input limits.
pub(crate) fn validate_decoded_item_random(random: &[u8]) -> Result<(), MdocEnvelopeError> {
    if random.is_empty() {
        return Err(MdocEnvelopeError::InvalidInput(
            MdocInvalidInputReason::EmptyRandom,
        ));
    }
    if random.len() < MIN_MDOC_ITEM_RANDOM_BYTES {
        return Err(MdocEnvelopeError::InvalidInput(
            MdocInvalidInputReason::InvalidRandomLength,
        ));
    }

    Ok(())
}

#[cfg(test)]
#[path = "validate_item_random_tests.rs"]
mod tests;
