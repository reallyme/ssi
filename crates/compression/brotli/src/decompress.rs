// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::io::Read;

use brotli::Decompressor;

use crate::BrotliError;

const BROTLI_BUFFER_SIZE: usize = 4096;

/// Default maximum decompressed payload size.
///
/// Sixteen MiB is intentionally much larger than normal identity envelopes but
/// still provides a hard memory bound for hostile compressed input.
pub const DEFAULT_MAX_DECOMPRESSED_BYTES: usize = 16 * 1024 * 1024;

/// Decompress Brotli-compressed bytes with the default output cap.
///
/// The cap is part of the security boundary: identity payloads may be received
/// from untrusted peers, and Brotli streams can expand far beyond their encoded
/// size. Use `brotli_decompress_with_limit` when a schema has a tighter maximum.
pub fn brotli_decompress(data: &[u8]) -> Result<Vec<u8>, BrotliError> {
    brotli_decompress_with_limit(data, DEFAULT_MAX_DECOMPRESSED_BYTES)
}

/// Decompress Brotli-compressed bytes with an explicit maximum output size.
///
/// The reader is allowed to produce one sentinel byte beyond the configured
/// limit so oversized streams are rejected deterministically instead of being
/// truncated.
pub fn brotli_decompress_with_limit(
    data: &[u8],
    max_output_len: usize,
) -> Result<Vec<u8>, BrotliError> {
    let read_limit = max_output_len
        .checked_add(1)
        .ok_or(BrotliError::OutputTooLarge)?;
    let read_limit = u64::try_from(read_limit).map_err(|_| BrotliError::OutputTooLarge)?;
    let reader = Decompressor::new(data, BROTLI_BUFFER_SIZE);
    let mut bounded_reader = reader.take(read_limit);
    let mut out = Vec::new();

    bounded_reader
        .read_to_end(&mut out)
        .map_err(|_| BrotliError::DecompressionFailed)?;

    if out.len() > max_output_len {
        return Err(BrotliError::OutputTooLarge);
    }

    Ok(out)
}
