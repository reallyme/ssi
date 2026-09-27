// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(clippy::indexing_slicing, clippy::unwrap_used)]

use super::{
    bech32_encode, bech32_values, create_checksum, decode_bech32_payload, DidMeErrorReason,
    BECH32_CHARSET, BECH32_CHECKSUM_LEN,
};

#[test]
fn decoder_rejects_zero_group_padding_alias() {
    let encoded = bech32_encode("me", &[0x5a; 16]).unwrap();
    let (_, data) = encoded.split_once('1').unwrap();
    let mut values = bech32_values(data.as_bytes()).unwrap();
    values.truncate(values.len() - BECH32_CHECKSUM_LEN);
    values.push(0);
    values.extend_from_slice(&create_checksum("me", &values).unwrap());

    let mut alias = String::from("me1");
    for value in values {
        alias.push(char::from(BECH32_CHARSET[usize::from(value)]));
    }

    assert_eq!(
        decode_bech32_payload(&alias, "me").unwrap_err().reason,
        DidMeErrorReason::InvalidData
    );
}

#[test]
fn decoder_rejects_wrong_hrp() {
    let encoded = bech32_encode("me", &[0x5a; 16]).unwrap();
    let wrong_hrp = encoded.replacen("me1", "id1", 1);
    assert_eq!(
        decode_bech32_payload(&wrong_hrp, "me").unwrap_err().reason,
        DidMeErrorReason::InvalidHrp
    );
}

#[test]
fn decoder_rejects_invalid_charset() {
    let encoded = bech32_encode("me", &[0x5a; 16]).unwrap();
    let mut invalid = encoded.into_bytes();
    invalid[3] = b'i';
    let invalid = String::from_utf8(invalid).unwrap();
    assert_eq!(
        decode_bech32_payload(&invalid, "me").unwrap_err().reason,
        DidMeErrorReason::InvalidCharacter
    );
}

#[test]
fn decoder_rejects_non_zero_padding_bits_with_a_valid_checksum() {
    let encoded = bech32_encode("me", &[0x5a; 16]).unwrap();
    let (_, data) = encoded.split_once('1').unwrap();
    let mut values = bech32_values(data.as_bytes()).unwrap();
    values.truncate(values.len() - BECH32_CHECKSUM_LEN);
    let last = values.last_mut().unwrap();
    *last |= 1;
    values.extend_from_slice(&create_checksum("me", &values).unwrap());

    let mut non_canonical = String::from("me1");
    for value in values {
        non_canonical.push(char::from(BECH32_CHARSET[usize::from(value)]));
    }
    assert_eq!(
        decode_bech32_payload(&non_canonical, "me")
            .unwrap_err()
            .reason,
        DidMeErrorReason::InvalidData
    );
}

#[test]
fn decoder_rejects_over_length_and_missing_separator() {
    let over_length = format!("me1{}", "q".repeat(88));
    assert_eq!(
        decode_bech32_payload(&over_length, "me")
            .unwrap_err()
            .reason,
        DidMeErrorReason::IdentifierTooLong
    );
    assert_eq!(
        decode_bech32_payload("meqqqqqq", "me").unwrap_err().reason,
        DidMeErrorReason::InvalidHrp
    );
}
