// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(clippy::expect_used)]

use super::{pack_token_status_values, token_status_value};
use crate::{TokenStatusBits, TokenStatusListError, TokenStatusListInvalidReason};

#[test]
fn extracts_each_supported_packed_value_width() {
    for (bits, values) in [
        (TokenStatusBits::One, vec![0, 1, 1, 0]),
        (TokenStatusBits::Two, vec![0, 1, 2, 3]),
        (TokenStatusBits::Four, vec![0, 7, 15]),
        (TokenStatusBits::Eight, vec![0, 127, 255]),
    ] {
        let packed = pack_token_status_values(&values, bits).expect("values must pack");
        for (index, expected) in values.iter().copied().enumerate() {
            assert_eq!(
                token_status_value(&packed, bits, index).expect("index must resolve"),
                expected
            );
        }
    }
    assert_eq!(
        token_status_value(&[0], TokenStatusBits::Eight, 1),
        Err(TokenStatusListError::InvalidInput(
            TokenStatusListInvalidReason::InvalidIndex
        ))
    );
}
