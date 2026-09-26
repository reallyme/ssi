// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Minimal strict CBOR reader shared by the COSE_Sign1 and CWT decoders.
//!
//! Only definite-length, shortest-form (RFC 8949 section 4.2.1) heads are
//! accepted; indefinite lengths and reserved additional-information values are
//! rejected.

use crate::{RegistrationError, RegistrationErrorReason};

pub(super) struct Decoder<'a> {
    input: &'a [u8],
    offset: usize,
}

impl<'a> Decoder<'a> {
    pub(super) const fn new(input: &'a [u8]) -> Self {
        Self { input, offset: 0 }
    }

    pub(super) fn peek_major_type(&self) -> Result<Option<u8>, RegistrationError> {
        Ok(self.input.get(self.offset).map(|value| value >> 5))
    }

    pub(super) fn read_tag(&mut self) -> Result<u64, RegistrationError> {
        self.read_expected_argument(6)
    }

    pub(super) fn read_array_length(&mut self) -> Result<usize, RegistrationError> {
        self.read_length(4)
    }

    pub(super) fn read_map_length(&mut self) -> Result<usize, RegistrationError> {
        self.read_length(5)
    }

    pub(super) fn read_byte_string(&mut self) -> Result<&'a [u8], RegistrationError> {
        let length = self.read_length(2)?;
        self.take(length)
    }

    pub(super) fn read_text_string(&mut self) -> Result<&'a str, RegistrationError> {
        let length = self.read_length(3)?;
        let bytes = self.take(length)?;
        core::str::from_utf8(bytes).map_err(|_error| invalid(RegistrationErrorReason::InvalidField))
    }

    pub(super) fn read_unsigned(&mut self) -> Result<u64, RegistrationError> {
        self.read_expected_argument(0)
    }

    pub(super) fn read_integer(&mut self) -> Result<i64, RegistrationError> {
        let (major, value) = self.read_head()?;
        match major {
            0 => i64::try_from(value)
                .map_err(|_error| invalid(RegistrationErrorReason::InvalidField)),
            1 => {
                let magnitude = i64::try_from(value)
                    .map_err(|_error| invalid(RegistrationErrorReason::InvalidField))?;
                (-1_i64)
                    .checked_sub(magnitude)
                    .ok_or_else(|| invalid(RegistrationErrorReason::InvalidField))
            }
            _ => Err(invalid(RegistrationErrorReason::InvalidField)),
        }
    }

    fn read_length(&mut self, expected_major: u8) -> Result<usize, RegistrationError> {
        let value = self.read_expected_argument(expected_major)?;
        usize::try_from(value).map_err(|_error| invalid(RegistrationErrorReason::InputTooLarge))
    }

    fn read_expected_argument(&mut self, expected_major: u8) -> Result<u64, RegistrationError> {
        let (major, value) = self.read_head()?;
        if major != expected_major {
            return Err(invalid(RegistrationErrorReason::InvalidField));
        }
        Ok(value)
    }

    pub(super) fn read_head(&mut self) -> Result<(u8, u64), RegistrationError> {
        let initial = self.read_byte()?;
        let major = initial >> 5;
        let additional = initial & 0x1f;
        let value = match additional {
            0..=23 => u64::from(additional),
            24 => {
                let value = u64::from(self.read_byte()?);
                if value < 24 {
                    return Err(invalid(RegistrationErrorReason::InvalidField));
                }
                value
            }
            25 => {
                let bytes = <[u8; 2]>::try_from(self.take(2)?)
                    .map_err(|_error| invalid(RegistrationErrorReason::InvalidField))?;
                let value = u64::from(u16::from_be_bytes(bytes));
                if value <= u64::from(u8::MAX) {
                    return Err(invalid(RegistrationErrorReason::InvalidField));
                }
                value
            }
            26 => {
                let bytes = <[u8; 4]>::try_from(self.take(4)?)
                    .map_err(|_error| invalid(RegistrationErrorReason::InvalidField))?;
                let value = u64::from(u32::from_be_bytes(bytes));
                if value <= u64::from(u16::MAX) {
                    return Err(invalid(RegistrationErrorReason::InvalidField));
                }
                value
            }
            27 => {
                let bytes = <[u8; 8]>::try_from(self.take(8)?)
                    .map_err(|_error| invalid(RegistrationErrorReason::InvalidField))?;
                let value = u64::from_be_bytes(bytes);
                if value <= u64::from(u32::MAX) {
                    return Err(invalid(RegistrationErrorReason::InvalidField));
                }
                value
            }
            _ => return Err(invalid(RegistrationErrorReason::InvalidField)),
        };
        Ok((major, value))
    }

    fn read_byte(&mut self) -> Result<u8, RegistrationError> {
        let value = self
            .input
            .get(self.offset)
            .copied()
            .ok_or_else(|| invalid(RegistrationErrorReason::InvalidField))?;
        self.offset = self
            .offset
            .checked_add(1)
            .ok_or_else(|| invalid(RegistrationErrorReason::InputTooLarge))?;
        Ok(value)
    }

    pub(super) fn take(&mut self, length: usize) -> Result<&'a [u8], RegistrationError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or_else(|| invalid(RegistrationErrorReason::InputTooLarge))?;
        let value = self
            .input
            .get(self.offset..end)
            .ok_or_else(|| invalid(RegistrationErrorReason::InvalidField))?;
        self.offset = end;
        Ok(value)
    }

    pub(super) const fn is_finished(&self) -> bool {
        self.offset == self.input.len()
    }
}

const fn invalid(reason: RegistrationErrorReason) -> RegistrationError {
    RegistrationError::from_reason(reason)
}
