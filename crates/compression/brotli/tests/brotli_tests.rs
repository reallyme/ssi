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

    assert_eq!(decompressed.as_slice(), input);
}

#[test]
fn strict_decompress_rejects_plain_data() {
    let input = b"not compressed at all";

    let result = brotli_decompress(input);

    assert_eq!(result, Err(BrotliError::DecompressionFailed));
}

#[test]
fn strict_decompress_rejects_trailing_data() {
    let mut compressed = brotli_compress(b"identity payload").unwrap();
    compressed.extend_from_slice(b"trailing");

    assert_eq!(
        brotli_decompress(&compressed),
        Err(BrotliError::TrailingData)
    );
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

    assert_eq!(decompressed.as_slice(), input.as_slice());
}

#[test]
fn decompression_growth_preserves_output_larger_than_initial_buffer() {
    let input = vec![0x5a_u8; 8 * 1024];
    let compressed = brotli_compress(&input).unwrap();

    let decompressed = brotli_decompress_with_limit(&compressed, input.len()).unwrap();

    assert_eq!(decompressed.as_slice(), input.as_slice());
}

#[test]
fn decompression_growth_rejects_output_above_large_explicit_limit() {
    let input = vec![0x5a_u8; 8 * 1024];
    let compressed = brotli_compress(&input).unwrap();

    assert_eq!(
        brotli_decompress_with_limit(&compressed, 4 * 1024),
        Err(BrotliError::OutputTooLarge)
    );
}

#[test]
fn small_decompression_does_not_retain_the_default_limit_capacity() {
    let input = b"small identity payload";
    let compressed = brotli_compress(input).unwrap();

    let decompressed = brotli_decompress(&compressed).unwrap();

    assert_eq!(decompressed.as_slice(), input);
    assert!(decompressed.capacity() <= 4 * 1024);
}

#[test]
fn decompression_rejects_non_standard_large_window_stream() {
    // WBITS=30 using Brotli's large-window extension, followed by two
    // one-byte metablocks. Permissive decoders allocate roughly 1 GiB before
    // producing the two output bytes.
    let hostile = [
        0x11, 0x1e, 0x00, 0x00, 0x02, 0x41, 0x00, 0x00, 0x08, 0x42, 0x03,
    ];

    assert_eq!(
        brotli_decompress_with_limit(&hostile, 2 * 1024 * 1024),
        Err(BrotliError::DecompressionFailed)
    );
}
