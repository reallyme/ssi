// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{parse_decimal_u8, parse_seconds};

#[test]
fn seconds_accept_fractional_generalized_time() {
    assert_eq!(parse_seconds("20"), Some(20));
    assert_eq!(parse_seconds("20.5"), Some(20));
    assert_eq!(parse_seconds("07.123456"), Some(7));
}

#[test]
fn seconds_reject_malformed_fractions() {
    for value in ["", "20.", ".5", "20.5a", "2a", "+2", "20.-1", "20.5.1"] {
        assert_eq!(parse_seconds(value), None, "{value}");
    }
}

#[test]
fn decimal_fields_reject_signs_and_non_digits() {
    for value in ["", "+1", "-1", "1 ", "0x1", "256"] {
        assert_eq!(parse_decimal_u8(value), None, "{value}");
    }
    assert_eq!(parse_decimal_u8("09"), Some(9));
}
