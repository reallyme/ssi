// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use core::cell::Cell;
use core::mem::size_of;
use std::rc::Rc;

use brotli::Allocator;

use super::{brotli_decompress_with_allocators, BrotliError, StandardAlloc};

struct CountingAllocator {
    requested_bytes: Rc<Cell<usize>>,
    inner: StandardAlloc,
}

impl CountingAllocator {
    fn new(requested_bytes: Rc<Cell<usize>>) -> Self {
        Self {
            requested_bytes,
            inner: StandardAlloc::default(),
        }
    }
}

impl<T> Allocator<T> for CountingAllocator
where
    T: Clone + Default,
    StandardAlloc: Allocator<T>,
{
    type AllocatedMemory = <StandardAlloc as Allocator<T>>::AllocatedMemory;

    fn alloc_cell(&mut self, len: usize) -> Self::AllocatedMemory {
        let requested = len.saturating_mul(size_of::<T>());
        self.requested_bytes
            .set(self.requested_bytes.get().saturating_add(requested));
        self.inner.alloc_cell(len)
    }

    fn free_cell(&mut self, data: Self::AllocatedMemory) {
        self.inner.free_cell(data);
    }
}

#[test]
fn oversized_rfc_window_is_rejected_before_decoder_allocation() {
    let requested_bytes = Rc::new(Cell::new(0));
    let hostile = [0x0f, 0x00, 0x80, 0x41, 0x00, 0x00, 0x08, 0x42, 0x03];
    let result = brotli_decompress_with_allocators(
        &hostile,
        64,
        CountingAllocator::new(Rc::clone(&requested_bytes)),
        CountingAllocator::new(Rc::clone(&requested_bytes)),
        CountingAllocator::new(Rc::clone(&requested_bytes)),
    );

    assert_eq!(result, Err(BrotliError::WindowTooLarge));
    // Total requested bytes upper-bounds peak live bytes. No decoder
    // allocation is permitted before the stream's WBITS is accepted.
    assert!(requested_bytes.get() <= 128);
}
