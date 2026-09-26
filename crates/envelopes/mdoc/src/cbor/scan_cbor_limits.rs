// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Bounded, non-allocating structural pre-scan of untrusted CBOR.
//!
//! Tree decoders allocate one value per data item and may reserve buffers for
//! declared string lengths before the input is known to contain them. This
//! walker visits every data item header without allocating, and rejects input
//! whose nesting depth, container sizes, total item count, or declared lengths
//! exceed the mdoc boundary profile before any value tree is built.

use crate::model::{
    MAX_MDOC_CBOR_ARRAY_ITEMS, MAX_MDOC_CBOR_DEPTH, MAX_MDOC_CBOR_ITEMS, MAX_MDOC_CBOR_MAP_ENTRIES,
};
use crate::{MdocEnvelopeError, MdocInvalidInputReason};

/// Bit shift that isolates the CBOR major type from an initial byte.
const MAJOR_TYPE_SHIFT: u8 = 5;
/// Mask that isolates the CBOR additional information from an initial byte.
const ADDITIONAL_INFO_MASK: u8 = 0x1f;

const MAJOR_UNSIGNED_INTEGER: u8 = 0;
const MAJOR_NEGATIVE_INTEGER: u8 = 1;
const MAJOR_BYTE_STRING: u8 = 2;
const MAJOR_TEXT_STRING: u8 = 3;
const MAJOR_ARRAY: u8 = 4;
const MAJOR_MAP: u8 = 5;
const MAJOR_TAG: u8 = 6;
const MAJOR_SIMPLE_OR_FLOAT: u8 = 7;

/// Largest additional-information value that encodes its argument inline.
const MAX_INLINE_ARGUMENT: u8 = 23;
const ARGUMENT_ONE_BYTE: u8 = 24;
const ARGUMENT_TWO_BYTES: u8 = 25;
const ARGUMENT_FOUR_BYTES: u8 = 26;
const ARGUMENT_EIGHT_BYTES: u8 = 27;
const ARGUMENT_INDEFINITE: u8 = 31;

/// Initial byte that terminates an indefinite-length item.
const BREAK_BYTE: u8 = 0xff;
/// RFC 8949 §3.3: one-byte simple values below 32 are not well-formed.
const MIN_ONE_BYTE_SIMPLE_VALUE: u64 = 32;
/// Each map entry is a key item followed by a value item.
const ITEMS_PER_MAP_ENTRY: usize = 2;

/// Reject CBOR input that exceeds the mdoc structural limits.
///
/// The input must hold exactly one well-formed data item with no trailing
/// bytes. Truncated or malformed encodings return [`MdocEnvelopeError::Cbor`];
/// limit violations return the matching typed [`MdocInvalidInputReason`].
pub(super) fn scan_cbor_limits(bytes: &[u8]) -> Result<(), MdocEnvelopeError> {
    let mut scanner = CborLimitScanner {
        bytes,
        offset: 0,
        items: 0,
    };
    scanner.scan_item(0)?;
    if scanner.offset != bytes.len() {
        return Err(MdocEnvelopeError::Cbor);
    }

    Ok(())
}

enum Argument {
    Definite(u64),
    Indefinite,
}

struct Header {
    major: u8,
    argument: Argument,
}

struct CborLimitScanner<'a> {
    bytes: &'a [u8],
    offset: usize,
    items: usize,
}

impl CborLimitScanner<'_> {
    fn scan_item(&mut self, depth: usize) -> Result<(), MdocEnvelopeError> {
        if depth > MAX_MDOC_CBOR_DEPTH {
            return Err(invalid(MdocInvalidInputReason::CborDepthExceeded));
        }
        self.count_item()?;
        let header = self.read_header()?;
        let child_depth = depth
            .checked_add(1)
            .ok_or(invalid(MdocInvalidInputReason::CborDepthExceeded))?;
        match (header.major, header.argument) {
            (MAJOR_UNSIGNED_INTEGER | MAJOR_NEGATIVE_INTEGER, Argument::Definite(_)) => Ok(()),
            (MAJOR_BYTE_STRING | MAJOR_TEXT_STRING, Argument::Definite(len)) => self.skip(len),
            (MAJOR_BYTE_STRING | MAJOR_TEXT_STRING, Argument::Indefinite) => {
                self.scan_indefinite_string(header.major)
            }
            (MAJOR_ARRAY, Argument::Definite(count)) => {
                self.scan_definite_array(count, child_depth)
            }
            (MAJOR_ARRAY, Argument::Indefinite) => self.scan_indefinite_array(child_depth),
            (MAJOR_MAP, Argument::Definite(count)) => self.scan_definite_map(count, child_depth),
            (MAJOR_MAP, Argument::Indefinite) => self.scan_indefinite_map(child_depth),
            (MAJOR_TAG, Argument::Definite(_)) => self.scan_item(child_depth),
            (MAJOR_SIMPLE_OR_FLOAT, Argument::Definite(_)) => Ok(()),
            _ => Err(MdocEnvelopeError::Cbor),
        }
    }

    fn scan_definite_array(&mut self, count: u64, depth: usize) -> Result<(), MdocEnvelopeError> {
        let count = usize::try_from(count)
            .map_err(|_| invalid(MdocInvalidInputReason::CborArrayTooLarge))?;
        if count > MAX_MDOC_CBOR_ARRAY_ITEMS {
            return Err(invalid(MdocInvalidInputReason::CborArrayTooLarge));
        }
        // Every item occupies at least one byte.
        if count > self.remaining()? {
            return Err(MdocEnvelopeError::Cbor);
        }
        for _ in 0..count {
            self.scan_item(depth)?;
        }

        Ok(())
    }

    fn scan_indefinite_array(&mut self, depth: usize) -> Result<(), MdocEnvelopeError> {
        let mut count = 0_usize;
        while !self.consume_break()? {
            if count >= MAX_MDOC_CBOR_ARRAY_ITEMS {
                return Err(invalid(MdocInvalidInputReason::CborArrayTooLarge));
            }
            count = count.checked_add(1).ok_or(MdocEnvelopeError::Cbor)?;
            self.scan_item(depth)?;
        }

        Ok(())
    }

    fn scan_definite_map(&mut self, count: u64, depth: usize) -> Result<(), MdocEnvelopeError> {
        let count =
            usize::try_from(count).map_err(|_| invalid(MdocInvalidInputReason::CborMapTooLarge))?;
        if count > MAX_MDOC_CBOR_MAP_ENTRIES {
            return Err(invalid(MdocInvalidInputReason::CborMapTooLarge));
        }
        // Every entry holds two items of at least one byte each.
        let minimum_bytes = count
            .checked_mul(ITEMS_PER_MAP_ENTRY)
            .ok_or(MdocEnvelopeError::Cbor)?;
        if minimum_bytes > self.remaining()? {
            return Err(MdocEnvelopeError::Cbor);
        }
        for _ in 0..count {
            self.scan_item(depth)?;
            self.scan_item(depth)?;
        }

        Ok(())
    }

    fn scan_indefinite_map(&mut self, depth: usize) -> Result<(), MdocEnvelopeError> {
        let mut count = 0_usize;
        while !self.consume_break()? {
            if count >= MAX_MDOC_CBOR_MAP_ENTRIES {
                return Err(invalid(MdocInvalidInputReason::CborMapTooLarge));
            }
            count = count.checked_add(1).ok_or(MdocEnvelopeError::Cbor)?;
            self.scan_item(depth)?;
            if self.peek()? == BREAK_BYTE {
                // A break between a key and its value leaves the entry incomplete.
                return Err(MdocEnvelopeError::Cbor);
            }
            self.scan_item(depth)?;
        }

        Ok(())
    }

    fn scan_indefinite_string(&mut self, major: u8) -> Result<(), MdocEnvelopeError> {
        while !self.consume_break()? {
            // Chunks do not become separate decoded values, but they are
            // counted so that chunk-heavy encodings stay within the work bound.
            self.count_item()?;
            let chunk = self.read_header()?;
            match (chunk.major == major, chunk.argument) {
                (true, Argument::Definite(len)) => self.skip(len)?,
                _ => return Err(MdocEnvelopeError::Cbor),
            }
        }

        Ok(())
    }

    fn read_header(&mut self) -> Result<Header, MdocEnvelopeError> {
        let initial = self.read_byte()?;
        let major = initial >> MAJOR_TYPE_SHIFT;
        let info = initial & ADDITIONAL_INFO_MASK;
        let argument = match info {
            0..=MAX_INLINE_ARGUMENT => Argument::Definite(u64::from(info)),
            ARGUMENT_ONE_BYTE => {
                let value = u64::from(self.read_byte()?);
                if major == MAJOR_SIMPLE_OR_FLOAT && value < MIN_ONE_BYTE_SIMPLE_VALUE {
                    return Err(MdocEnvelopeError::Cbor);
                }
                Argument::Definite(value)
            }
            ARGUMENT_TWO_BYTES => {
                Argument::Definite(u64::from(u16::from_be_bytes(self.read_array::<2>()?)))
            }
            ARGUMENT_FOUR_BYTES => {
                Argument::Definite(u64::from(u32::from_be_bytes(self.read_array::<4>()?)))
            }
            ARGUMENT_EIGHT_BYTES => Argument::Definite(u64::from_be_bytes(self.read_array::<8>()?)),
            ARGUMENT_INDEFINITE => Argument::Indefinite,
            _ => return Err(MdocEnvelopeError::Cbor),
        };

        Ok(Header { major, argument })
    }

    fn count_item(&mut self) -> Result<(), MdocEnvelopeError> {
        self.items = self
            .items
            .checked_add(1)
            .ok_or(invalid(MdocInvalidInputReason::CborTooManyItems))?;
        if self.items > MAX_MDOC_CBOR_ITEMS {
            return Err(invalid(MdocInvalidInputReason::CborTooManyItems));
        }

        Ok(())
    }

    /// Consume a break byte if one is next; fail on truncated input.
    fn consume_break(&mut self) -> Result<bool, MdocEnvelopeError> {
        if self.peek()? != BREAK_BYTE {
            return Ok(false);
        }
        self.advance(1)?;

        Ok(true)
    }

    fn peek(&self) -> Result<u8, MdocEnvelopeError> {
        self.bytes
            .get(self.offset)
            .copied()
            .ok_or(MdocEnvelopeError::Cbor)
    }

    fn read_byte(&mut self) -> Result<u8, MdocEnvelopeError> {
        let byte = self.peek()?;
        self.advance(1)?;

        Ok(byte)
    }

    fn read_array<const N: usize>(&mut self) -> Result<[u8; N], MdocEnvelopeError> {
        let end = self.offset.checked_add(N).ok_or(MdocEnvelopeError::Cbor)?;
        let slice = self
            .bytes
            .get(self.offset..end)
            .ok_or(MdocEnvelopeError::Cbor)?;
        let array = <[u8; N]>::try_from(slice).map_err(|_| MdocEnvelopeError::Cbor)?;
        self.offset = end;

        Ok(array)
    }

    /// Skip a declared string payload, which must fit in the remaining input.
    fn skip(&mut self, len: u64) -> Result<(), MdocEnvelopeError> {
        let len = usize::try_from(len).map_err(|_| MdocEnvelopeError::Cbor)?;
        if len > self.remaining()? {
            return Err(MdocEnvelopeError::Cbor);
        }
        self.advance(len)
    }

    fn advance(&mut self, len: usize) -> Result<(), MdocEnvelopeError> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or(MdocEnvelopeError::Cbor)?;
        if end > self.bytes.len() {
            return Err(MdocEnvelopeError::Cbor);
        }
        self.offset = end;

        Ok(())
    }

    fn remaining(&self) -> Result<usize, MdocEnvelopeError> {
        self.bytes
            .len()
            .checked_sub(self.offset)
            .ok_or(MdocEnvelopeError::Cbor)
    }
}

const fn invalid(reason: MdocInvalidInputReason) -> MdocEnvelopeError {
    MdocEnvelopeError::InvalidInput(reason)
}

#[cfg(test)]
#[path = "../scan_cbor_limits_tests.rs"]
mod tests;
