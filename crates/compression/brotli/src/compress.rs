// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::io::Cursor;

use brotli::enc::cluster::HistogramPair;
use brotli::enc::command::Command;
use brotli::enc::entropy_encode::HuffmanTree;
use brotli::enc::histogram::{ContextType, HistogramCommand, HistogramDistance, HistogramLiteral};
use brotli::enc::{
    floatX, s16, v8, BrotliAlloc, BrotliEncoderMaxCompressedSize, BrotliEncoderParams,
    StandardAlloc, StaticCommand, ZopfliNode, PDF,
};
use brotli::{Allocator, SliceWrapperMut};
use zeroize::{Zeroize, Zeroizing};

use crate::BrotliError;

const BROTLI_BUFFER_SIZE: usize = 4096;
const BROTLI_QUALITY_BEST: i32 = 11;
const BROTLI_LG_WINDOW_DEFAULT: i32 = 22;

#[derive(Default)]
struct ClearingBrotliAllocator {
    inner: StandardAlloc,
}

impl Allocator<u8> for ClearingBrotliAllocator {
    type AllocatedMemory = <StandardAlloc as Allocator<u8>>::AllocatedMemory;

    fn alloc_cell(&mut self, len: usize) -> Self::AllocatedMemory {
        self.inner.alloc_cell(len)
    }

    fn free_cell(&mut self, mut data: Self::AllocatedMemory) {
        data.slice_mut().zeroize();
        self.inner.free_cell(data);
    }
}

macro_rules! impl_clearing_allocator {
    ($($value_type:ty),+ $(,)?) => {
        $(
            impl Allocator<$value_type> for ClearingBrotliAllocator {
                type AllocatedMemory =
                    <StandardAlloc as Allocator<$value_type>>::AllocatedMemory;

                fn alloc_cell(&mut self, len: usize) -> Self::AllocatedMemory {
                    self.inner.alloc_cell(len)
                }

                fn free_cell(&mut self, mut data: Self::AllocatedMemory) {
                    data.slice_mut().fill_with(<$value_type>::default);
                    self.inner.free_cell(data);
                }
            }
        )+
    };
}

impl_clearing_allocator!(
    u16,
    i32,
    u32,
    u64,
    Command,
    floatX,
    v8,
    s16,
    PDF,
    StaticCommand,
    HistogramLiteral,
    HistogramCommand,
    HistogramDistance,
    HistogramPair,
    ContextType,
    HuffmanTree,
    ZopfliNode,
);

impl BrotliAlloc for ClearingBrotliAllocator {}

/// Compress bytes using Brotli at best compression.
///
/// Intended for arbitrary byte payloads. Protocol-specific framing and input
/// size policy remain the caller's responsibility.
pub fn brotli_compress(data: &[u8]) -> Result<Zeroizing<Vec<u8>>, BrotliError> {
    let maximum_size = BrotliEncoderMaxCompressedSize(data.len());
    if maximum_size == 0 {
        return Err(BrotliError::CompressionFailed);
    }
    let mut out = Zeroizing::new(Vec::new());
    out.try_reserve_exact(maximum_size)
        .map_err(|_| BrotliError::CompressionFailed)?;
    let mut input_buffer = Zeroizing::new([0_u8; BROTLI_BUFFER_SIZE]);
    let mut output_buffer = Zeroizing::new([0_u8; BROTLI_BUFFER_SIZE]);
    let mut input = Cursor::new(data);
    let params = BrotliEncoderParams {
        quality: BROTLI_QUALITY_BEST,
        lgwin: BROTLI_LG_WINDOW_DEFAULT,
        large_window: false,
        size_hint: data.len(),
        ..BrotliEncoderParams::default()
    };
    let output: &mut Vec<u8> = &mut out;
    brotli::BrotliCompressCustomAlloc(
        &mut input,
        output,
        &mut *input_buffer,
        &mut *output_buffer,
        &params,
        ClearingBrotliAllocator::default(),
    )
    .map_err(|_| BrotliError::CompressionFailed)?;
    Ok(out)
}
