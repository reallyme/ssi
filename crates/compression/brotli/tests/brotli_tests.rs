// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(missing_docs, clippy::expect_used, clippy::unwrap_used)]
//! Test coverage for this crate.

use reallyme_compression_brotli::{
    brotli_compress, brotli_decompress, brotli_decompress_with_limit, BrotliError,
};

#[test]
fn roundtrip_compression() {
    let input = b"hello world hello world hello world";

    let compressed = brotli_compress(input).unwrap();
    let decompressed = brotli_decompress(&compressed).unwrap();

    assert_eq!(decompressed, input);
}

#[test]
fn strict_decompress_rejects_plain_data() {
    let input = b"not compressed at all";

    let result = brotli_decompress(input);

    assert_eq!(result, Err(BrotliError::DecompressionFailed));
}

#[test]
fn compression_reduces_size_for_repetitive_data() {
    let input = vec![42u8; 10_000];

    let compressed = brotli_compress(&input).unwrap();

    assert!(compressed.len() < input.len());
}

#[test]
fn decompression_rejects_output_past_explicit_limit() {
    let input = vec![42u8; 128];
    let compressed = brotli_compress(&input).unwrap();

    let result = brotli_decompress_with_limit(&compressed, 64);

    assert_eq!(result, Err(BrotliError::OutputTooLarge));
}

#[test]
fn decompression_allows_output_at_explicit_limit() {
    let input = vec![42u8; 128];
    let compressed = brotli_compress(&input).unwrap();

    let decompressed = brotli_decompress_with_limit(&compressed, 128).unwrap();

    assert_eq!(decompressed, input);
}
