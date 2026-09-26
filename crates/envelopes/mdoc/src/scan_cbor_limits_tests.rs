// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::scan_cbor_limits;
use crate::cbor::cbor_bytes_to_value;
use crate::{
    MdocEnvelopeError, MdocInvalidInputReason, MAX_MDOC_CBOR_ARRAY_ITEMS, MAX_MDOC_CBOR_DEPTH,
    MAX_MDOC_CBOR_MAP_ENTRIES,
};

const ARRAY_TOO_LARGE: MdocEnvelopeError =
    MdocEnvelopeError::InvalidInput(MdocInvalidInputReason::CborArrayTooLarge);
const MAP_TOO_LARGE: MdocEnvelopeError =
    MdocEnvelopeError::InvalidInput(MdocInvalidInputReason::CborMapTooLarge);
const DEPTH_EXCEEDED: MdocEnvelopeError =
    MdocEnvelopeError::InvalidInput(MdocInvalidInputReason::CborDepthExceeded);
const TOO_MANY_ITEMS: MdocEnvelopeError =
    MdocEnvelopeError::InvalidInput(MdocInvalidInputReason::CborTooManyItems);

/// Encode a definite-length header with an explicit two-byte argument.
fn header_u16(major: u8, argument: u16) -> Vec<u8> {
    let mut out = vec![(major << 5) | 25];
    out.extend_from_slice(&argument.to_be_bytes());
    out
}

/// Encode a definite-length header with an explicit eight-byte argument.
fn header_u64(major: u8, argument: u64) -> Vec<u8> {
    let mut out = vec![(major << 5) | 27];
    out.extend_from_slice(&argument.to_be_bytes());
    out
}

fn array_of_zeros(count: u16) -> Vec<u8> {
    let mut out = header_u16(4, count);
    out.resize(out.len() + usize::from(count), 0x00);
    out
}

fn nested_arrays(depth: usize) -> Vec<u8> {
    let mut out = vec![0x81; depth];
    out.push(0x00);
    out
}

fn assert_both(bytes: &[u8], expected: MdocEnvelopeError) {
    assert_eq!(scan_cbor_limits(bytes), Err(expected));
    assert_eq!(cbor_bytes_to_value(bytes).err(), Some(expected));
}

#[test]
fn accepts_definite_and_indefinite_well_formed_items() {
    // {"a": [1, -1, h'00', "x", 1.5, true, null, 24(h'a0')]}
    let definite = [
        0xa1, 0x61, 0x61, 0x88, 0x01, 0x20, 0x41, 0x00, 0x61, 0x78, 0xf9, 0x3e, 0x00, 0xf5, 0xf6,
        0xd8, 0x18, 0x41, 0xa0,
    ];
    assert_eq!(scan_cbor_limits(&definite), Ok(()));
    assert!(cbor_bytes_to_value(&definite).is_ok());

    // {_ "a": [_ 1, 2], "b": (_ h'01', h'02')}
    let indefinite = [
        0xbf, 0x61, 0x61, 0x9f, 0x01, 0x02, 0xff, 0x61, 0x62, 0x5f, 0x41, 0x01, 0x41, 0x02, 0xff,
        0xff,
    ];
    assert_eq!(scan_cbor_limits(&indefinite), Ok(()));
    assert!(cbor_bytes_to_value(&indefinite).is_ok());
}

#[test]
fn accepts_maximum_depth_container_size_and_item_count() {
    assert_eq!(
        scan_cbor_limits(&nested_arrays(MAX_MDOC_CBOR_DEPTH)),
        Ok(())
    );
    assert!(cbor_bytes_to_value(&nested_arrays(MAX_MDOC_CBOR_DEPTH)).is_ok());

    let max_array = array_of_zeros(u16::try_from(MAX_MDOC_CBOR_ARRAY_ITEMS).unwrap_or(0));
    assert_eq!(scan_cbor_limits(&max_array), Ok(()));

    // 1 outer + 255 * (1 inner + 256 zeros) = 65_536 items.
    let mut max_items = header_u16(4, 255);
    for _ in 0..255 {
        max_items.extend_from_slice(&array_of_zeros(256));
    }
    assert_eq!(scan_cbor_limits(&max_items), Ok(()));
    assert!(cbor_bytes_to_value(&max_items).is_ok());
}

#[test]
fn rejects_item_count_amplification_before_decoding() {
    // One item past the bound: 255 full inner arrays plus one extra zero.
    let mut too_many = header_u16(4, 256);
    for _ in 0..255 {
        too_many.extend_from_slice(&array_of_zeros(256));
    }
    too_many.push(0x00);
    assert_both(&too_many, TOO_MANY_ITEMS);
}

#[test]
fn rejects_declared_string_lengths_beyond_remaining_input() {
    // Byte and text strings declaring 2^63 and 1 KiB payloads with 1 byte present.
    let mut huge_bytes = header_u64(2, 1 << 63);
    huge_bytes.push(0x00);
    assert_both(&huge_bytes, MdocEnvelopeError::Cbor);

    let mut short_text = header_u16(3, 1024);
    short_text.push(b'a');
    assert_both(&short_text, MdocEnvelopeError::Cbor);

    // An indefinite byte string whose chunk overruns the input.
    let mut chunked = vec![0x5f];
    chunked.extend_from_slice(&header_u16(2, 1024));
    chunked.push(0x00);
    assert_both(&chunked, MdocEnvelopeError::Cbor);
}

#[test]
fn rejects_oversized_and_implausible_container_counts() {
    assert_both(&header_u64(4, u64::MAX), ARRAY_TOO_LARGE);
    assert_both(&header_u64(5, u64::MAX), MAP_TOO_LARGE);

    let over_array = array_of_zeros(u16::try_from(MAX_MDOC_CBOR_ARRAY_ITEMS + 1).unwrap_or(0));
    assert_both(&over_array, ARRAY_TOO_LARGE);

    let mut over_map = header_u16(5, u16::try_from(MAX_MDOC_CBOR_MAP_ENTRIES + 1).unwrap_or(0));
    over_map.resize(over_map.len() + (MAX_MDOC_CBOR_MAP_ENTRIES + 1) * 2, 0x00);
    assert_both(&over_map, MAP_TOO_LARGE);

    // Within limits but declaring more items than bytes remain.
    let mut implausible_array = header_u16(4, 400);
    implausible_array.push(0x00);
    assert_both(&implausible_array, MdocEnvelopeError::Cbor);

    let mut implausible_map = header_u16(5, 300);
    implausible_map.extend_from_slice(&[0x00; 300]);
    assert_both(&implausible_map, MdocEnvelopeError::Cbor);
}

#[test]
fn rejects_indefinite_containers_past_limits() {
    let mut array = vec![0x9f];
    array.resize(1 + MAX_MDOC_CBOR_ARRAY_ITEMS + 1, 0x00);
    array.push(0xff);
    assert_both(&array, ARRAY_TOO_LARGE);

    let mut map = vec![0xbf];
    map.resize(1 + (MAX_MDOC_CBOR_MAP_ENTRIES + 1) * 2, 0x00);
    map.push(0xff);
    assert_both(&map, MAP_TOO_LARGE);
}

#[test]
fn rejects_excess_nesting_through_arrays_and_tags() {
    assert_both(&nested_arrays(MAX_MDOC_CBOR_DEPTH + 1), DEPTH_EXCEEDED);

    let mut tags = vec![0xc1; MAX_MDOC_CBOR_DEPTH + 1];
    tags.push(0x00);
    assert_both(&tags, DEPTH_EXCEEDED);

    let mut indefinite = vec![0x9f; MAX_MDOC_CBOR_DEPTH + 1];
    indefinite.push(0x00);
    indefinite.extend_from_slice(&[0xff; MAX_MDOC_CBOR_DEPTH + 1]);
    assert_both(&indefinite, DEPTH_EXCEEDED);
}

#[test]
fn rejects_malformed_encodings() {
    let cases: [&[u8]; 10] = [
        &[],
        // Reserved additional information values.
        &[0x1c],
        &[0x7e],
        // Indefinite length on integers and tags.
        &[0x1f],
        &[0xdf, 0x00],
        // Lone break and break between an indefinite map key and value.
        &[0xff],
        &[0xbf, 0x00, 0xff],
        // Indefinite string with a chunk of the wrong major type.
        &[0x5f, 0x61, 0x61, 0xff],
        // One-byte simple value below 32.
        &[0xf8, 0x10],
        // Trailing bytes after a complete item.
        &[0x00, 0x00],
    ];
    for bytes in cases {
        assert_both(bytes, MdocEnvelopeError::Cbor);
    }

    // Truncated argument and unterminated indefinite array.
    assert_both(&[0x19, 0x01], MdocEnvelopeError::Cbor);
    assert_both(&[0x9f, 0x00], MdocEnvelopeError::Cbor);
}
