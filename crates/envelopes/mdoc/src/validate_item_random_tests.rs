// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{validate_decoded_item_random, validate_issuance_item_random};
use crate::{
    MdocEnvelopeError, MdocInvalidInputReason, MAX_MDOC_ITEM_RANDOM_BYTES,
    MIN_MDOC_ITEM_RANDOM_BYTES,
};

const INVALID_LENGTH: MdocEnvelopeError =
    MdocEnvelopeError::InvalidInput(MdocInvalidInputReason::InvalidRandomLength);
const EMPTY: MdocEnvelopeError =
    MdocEnvelopeError::InvalidInput(MdocInvalidInputReason::EmptyRandom);

#[test]
fn issuance_random_accepts_inclusive_bounds() {
    assert_eq!(
        validate_issuance_item_random(&[0_u8; MIN_MDOC_ITEM_RANDOM_BYTES]),
        Ok(())
    );
    assert_eq!(
        validate_issuance_item_random(&[0_u8; MAX_MDOC_ITEM_RANDOM_BYTES]),
        Ok(())
    );
}

#[test]
fn issuance_random_rejects_empty_short_and_oversized_values() {
    assert_eq!(validate_issuance_item_random(&[]), Err(EMPTY));
    assert_eq!(
        validate_issuance_item_random(&[0_u8; 1]),
        Err(INVALID_LENGTH)
    );
    assert_eq!(
        validate_issuance_item_random(&[0_u8; MIN_MDOC_ITEM_RANDOM_BYTES - 1]),
        Err(INVALID_LENGTH)
    );
    assert_eq!(
        validate_issuance_item_random(&[0_u8; MAX_MDOC_ITEM_RANDOM_BYTES + 1]),
        Err(INVALID_LENGTH)
    );
}

#[test]
fn decoded_random_enforces_minimum_without_issuance_maximum() {
    assert_eq!(validate_decoded_item_random(&[]), Err(EMPTY));
    assert_eq!(
        validate_decoded_item_random(&[0_u8; MIN_MDOC_ITEM_RANDOM_BYTES - 1]),
        Err(INVALID_LENGTH)
    );
    assert_eq!(
        validate_decoded_item_random(&[0_u8; MAX_MDOC_ITEM_RANDOM_BYTES + 1]),
        Ok(())
    );
}
