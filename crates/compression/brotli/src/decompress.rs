// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use brotli::reader::StandardAlloc;
use brotli::{Allocator, BrotliDecompressStream, BrotliResult, BrotliState, HuffmanCode};
use zeroize::Zeroizing;

use crate::BrotliError;

/// Default maximum decompressed payload size.
///
/// Sixteen MiB is intentionally much larger than normal identity envelopes but
/// still provides a hard memory bound for hostile compressed input.
pub const DEFAULT_MAX_DECOMPRESSED_BYTES: usize = 16 * 1024 * 1024;
const INITIAL_OUTPUT_BUFFER_BYTES: usize = 4 * 1024;
const MINIMUM_DECODER_WINDOW_BYTES: usize = 64 * 1024;

/// Decompress Brotli-compressed bytes with the default output cap.
///
/// The cap is part of the security boundary: identity payloads may be received
/// from untrusted peers, and Brotli streams can expand far beyond their encoded
/// size. Use `brotli_decompress_with_limit` when a schema has a tighter maximum.
pub fn brotli_decompress(data: &[u8]) -> Result<Zeroizing<Vec<u8>>, BrotliError> {
    brotli_decompress_with_limit(data, DEFAULT_MAX_DECOMPRESSED_BYTES)
}

/// Decompress Brotli-compressed bytes with an explicit maximum output size.
///
/// The reader is allowed to produce one sentinel byte beyond the configured
/// limit so oversized streams are rejected deterministically instead of being
/// truncated. Returned plaintext and replacement output allocations are
/// zeroized. The Brotli decoder owns an internal ring buffer whose allocator
/// does not expose a reliable zeroization hook; callers that require stronger
/// process-memory isolation must run decompression in a disposable process.
pub fn brotli_decompress_with_limit(
    data: &[u8],
    max_output_len: usize,
) -> Result<Zeroizing<Vec<u8>>, BrotliError> {
    brotli_decompress_with_allocators(
        data,
        max_output_len,
        StandardAlloc::default(),
        StandardAlloc::default(),
        StandardAlloc::default(),
    )
}

fn brotli_decompress_with_allocators<AllocU8, AllocU32, AllocHC>(
    data: &[u8],
    max_output_len: usize,
    alloc_u8: AllocU8,
    alloc_u32: AllocU32,
    alloc_hc: AllocHC,
) -> Result<Zeroizing<Vec<u8>>, BrotliError>
where
    AllocU8: Allocator<u8>,
    AllocU32: Allocator<u32>,
    AllocHC: Allocator<HuffmanCode>,
{
    validate_decoder_window(data, max_output_len)?;
    let output_limit = max_output_len
        .checked_add(1)
        .ok_or(BrotliError::OutputTooLarge)?;
    // The permissive constructor enables Brotli's non-standard large-window
    // extension. A tiny hostile stream can then request a 1 GiB ring buffer
    // before the output cap is consulted. Strict mode accepts only RFC 7932
    // windows (WBITS <= 24), keeping decoder memory within the protocol bound.
    let mut state = BrotliState::new_strict(alloc_u8, alloc_u32, alloc_hc);
    let mut available_in = data.len();
    let mut input_offset = 0usize;
    let mut total_out = 0usize;
    // Grow in bounded steps. Each replacement allocation is owned by a
    // Zeroizing wrapper, so plaintext left in the previous allocation is
    // cleared before the allocator can reuse it.
    let initial_len = output_limit.min(INITIAL_OUTPUT_BUFFER_BYTES);
    let mut out = allocate_zeroed(initial_len)?;
    let mut output_offset = 0usize;
    loop {
        let remaining_output = out
            .len()
            .checked_sub(output_offset)
            .ok_or(BrotliError::OutputTooLarge)?;
        if remaining_output == 0 {
            grow_output(&mut out, output_limit, output_offset)?;
            continue;
        }
        let mut available_out = remaining_output;
        let result = BrotliDecompressStream(
            &mut available_in,
            &mut input_offset,
            data,
            &mut available_out,
            &mut output_offset,
            out.as_mut_slice(),
            &mut total_out,
            &mut state,
        );
        if output_offset > max_output_len {
            return Err(BrotliError::OutputTooLarge);
        }
        match result {
            BrotliResult::ResultSuccess => {
                if input_offset != data.len() {
                    return Err(BrotliError::TrailingData);
                }
                return right_size_output(&out, output_offset);
            }
            BrotliResult::ResultFailure => return Err(BrotliError::DecompressionFailed),
            BrotliResult::NeedsMoreInput if available_in == 0 => {
                return Err(BrotliError::DecompressionFailed);
            }
            BrotliResult::NeedsMoreInput | BrotliResult::NeedsMoreOutput => {}
        }
    }
}

fn validate_decoder_window(data: &[u8], max_output_len: usize) -> Result<(), BrotliError> {
    let first = data
        .first()
        .copied()
        .ok_or(BrotliError::DecompressionFailed)?;
    let window_bits = if first & 1 == 0 {
        16_u32
    } else {
        let first_extension = (first >> 1) & 0b111;
        if first_extension != 0 {
            17_u32
                .checked_add(u32::from(first_extension))
                .ok_or(BrotliError::DecompressionFailed)?
        } else {
            let second_extension = (first >> 4) & 0b111;
            match second_extension {
                // This bit pattern introduces Brotli's non-standard large
                // window extension and is invalid in strict RFC 7932 mode.
                1 => return Err(BrotliError::DecompressionFailed),
                0 => 17,
                value => 8_u32
                    .checked_add(u32::from(value))
                    .ok_or(BrotliError::DecompressionFailed)?,
            }
        }
    };
    let decoder_window = 1_usize
        .checked_shl(window_bits)
        .ok_or(BrotliError::WindowTooLarge)?;
    let allowed_window = max_output_len.max(MINIMUM_DECODER_WINDOW_BYTES);
    if decoder_window > allowed_window {
        return Err(BrotliError::WindowTooLarge);
    }
    Ok(())
}

fn allocate_zeroed(len: usize) -> Result<Zeroizing<Vec<u8>>, BrotliError> {
    let mut storage = Vec::new();
    storage
        .try_reserve_exact(len)
        .map_err(|_| BrotliError::OutputTooLarge)?;
    storage.resize(len, 0);
    Ok(Zeroizing::new(storage))
}

fn grow_output(
    output: &mut Zeroizing<Vec<u8>>,
    output_limit: usize,
    initialized_len: usize,
) -> Result<(), BrotliError> {
    if output.len() >= output_limit {
        return Err(BrotliError::OutputTooLarge);
    }
    let doubled = output
        .len()
        .checked_mul(2)
        .ok_or(BrotliError::OutputTooLarge)?;
    let next_len = doubled.max(1).min(output_limit);
    let mut replacement = allocate_zeroed(next_len)?;
    let destination = replacement
        .get_mut(..initialized_len)
        .ok_or(BrotliError::OutputTooLarge)?;
    let source = output
        .get(..initialized_len)
        .ok_or(BrotliError::OutputTooLarge)?;
    destination.copy_from_slice(source);
    *output = replacement;
    Ok(())
}

fn right_size_output(
    output: &[u8],
    initialized_len: usize,
) -> Result<Zeroizing<Vec<u8>>, BrotliError> {
    let source = output
        .get(..initialized_len)
        .ok_or(BrotliError::OutputTooLarge)?;
    let mut result = Vec::new();
    result
        .try_reserve_exact(initialized_len)
        .map_err(|_| BrotliError::OutputTooLarge)?;
    result.extend_from_slice(source);
    Ok(Zeroizing::new(result))
}

#[cfg(test)]
#[path = "decompress_tests.rs"]
mod tests;
