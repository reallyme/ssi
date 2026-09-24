// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::{ClaimPath, ClaimPathSegment, ClaimsError, ClaimsInvalidReason};
use std::collections::BTreeMap;
use time::format_description::well_known::Rfc3339;
use time::{Date, Month, OffsetDateTime};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Maximum UTF-8 bytes accepted for one string-like claim value.
pub const MAX_CLAIM_STRING_BYTES: usize = 4096;

/// Maximum bytes accepted for one opaque byte claim value.
pub const MAX_CLAIM_BYTES_VALUE_BYTES: usize = 4096;

/// Maximum array items accepted in one claim value.
pub const MAX_CLAIM_ARRAY_ITEMS: usize = 256;

/// Maximum object members accepted in one claim value.
pub const MAX_CLAIM_OBJECT_PROPERTIES: usize = 512;

/// Maximum recursive depth accepted in a normalized claim value.
pub const MAX_CLAIM_VALUE_DEPTH: usize = 32;

const MAX_DECIMAL_BYTES: usize = 128;
const DATE_LEN: usize = 10;

/// Protocol-neutral normalized credential claim value.
///
/// Values may contain identity data. The type intentionally redacts `Debug`
/// output and zeroizes owned buffers on drop so payload normalization does not
/// become an accidental long-lived copy of PII.
#[derive(Eq, PartialEq)]
pub enum ClaimValue {
    /// Null value.
    Null,

    /// Boolean value.
    Boolean(bool),

    /// UTF-8 string value.
    String(String),

    /// Signed integer value.
    Signed(i64),

    /// Unsigned integer value.
    Unsigned(u64),

    /// Canonical fixed-point decimal value.
    Decimal(ClaimDecimal),

    /// Opaque byte string value.
    Bytes(Vec<u8>),

    /// ISO 8601 calendar date value.
    Date(ClaimDate),

    /// RFC 3339 date-time value.
    DateTime(ClaimDateTime),

    /// Ordered array value.
    Array(Vec<ClaimValue>),

    /// Object value with deterministic member ordering.
    Object(BTreeMap<String, ClaimValue>),
}

/// Canonical fixed-point decimal claim value.
#[derive(Eq, PartialEq)]
pub struct ClaimDecimal {
    lexical: String,
}

/// ISO 8601 calendar date claim value.
#[derive(Eq, PartialEq)]
pub struct ClaimDate {
    iso8601: String,
}

/// RFC 3339 date-time claim value.
#[derive(Eq, PartialEq)]
pub struct ClaimDateTime {
    rfc3339: String,
}

impl ClaimValue {
    /// Normalize an untyped JSON value into the protocol-neutral model.
    pub fn from_json(value: &serde_json::Value) -> Result<Self, ClaimsError> {
        crate::json::claim_value_from_json(value)
    }

    /// Resolve a canonical path inside this normalized value.
    pub fn resolve_path<'a>(
        &'a self,
        path: &ClaimPath,
    ) -> Result<Option<&'a ClaimValue>, ClaimsError> {
        resolve_claim_path(self, path)
    }
}

impl ClaimDecimal {
    /// Construct a decimal after canonical lexical validation.
    pub fn new(value: impl Into<String>) -> Result<Self, ClaimsError> {
        let lexical = value.into();
        validate_decimal(lexical.as_str())?;
        Ok(Self { lexical })
    }

    /// Return the canonical decimal spelling.
    pub fn as_str(&self) -> &str {
        self.lexical.as_str()
    }
}

impl ClaimDate {
    /// Construct a date after ISO 8601 calendar-date validation.
    pub fn new(value: impl Into<String>) -> Result<Self, ClaimsError> {
        let iso8601 = value.into();
        validate_date(iso8601.as_str())?;
        Ok(Self { iso8601 })
    }

    /// Return the ISO 8601 calendar date spelling.
    pub fn as_str(&self) -> &str {
        self.iso8601.as_str()
    }
}

impl ClaimDateTime {
    /// Construct a date-time after RFC 3339 validation.
    pub fn new(value: impl Into<String>) -> Result<Self, ClaimsError> {
        let rfc3339 = value.into();
        validate_date_time(rfc3339.as_str())?;
        Ok(Self { rfc3339 })
    }

    /// Return the RFC 3339 date-time spelling.
    pub fn as_str(&self) -> &str {
        self.rfc3339.as_str()
    }
}

impl core::fmt::Debug for ClaimValue {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Null => formatter.write_str("ClaimValue::Null"),
            Self::Boolean(_) => formatter.write_str("ClaimValue::Boolean(<redacted>)"),
            Self::String(value) => formatter
                .debug_tuple("ClaimValue::String")
                .field(&redacted_len(value.len()))
                .finish(),
            Self::Signed(_) => formatter.write_str("ClaimValue::Signed(<redacted>)"),
            Self::Unsigned(_) => formatter.write_str("ClaimValue::Unsigned(<redacted>)"),
            Self::Decimal(value) => formatter
                .debug_tuple("ClaimValue::Decimal")
                .field(&redacted_len(value.lexical.len()))
                .finish(),
            Self::Bytes(value) => formatter
                .debug_tuple("ClaimValue::Bytes")
                .field(&redacted_len(value.len()))
                .finish(),
            Self::Date(value) => formatter
                .debug_tuple("ClaimValue::Date")
                .field(&redacted_len(value.iso8601.len()))
                .finish(),
            Self::DateTime(value) => formatter
                .debug_tuple("ClaimValue::DateTime")
                .field(&redacted_len(value.rfc3339.len()))
                .finish(),
            Self::Array(values) => formatter
                .debug_tuple("ClaimValue::Array")
                .field(&redacted_len(values.len()))
                .finish(),
            Self::Object(values) => formatter
                .debug_tuple("ClaimValue::Object")
                .field(&redacted_len(values.len()))
                .finish(),
        }
    }
}

impl core::fmt::Debug for ClaimDecimal {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_tuple("ClaimDecimal")
            .field(&redacted_len(self.lexical.len()))
            .finish()
    }
}

impl core::fmt::Debug for ClaimDate {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_tuple("ClaimDate")
            .field(&redacted_len(self.iso8601.len()))
            .finish()
    }
}

impl core::fmt::Debug for ClaimDateTime {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_tuple("ClaimDateTime")
            .field(&redacted_len(self.rfc3339.len()))
            .finish()
    }
}

impl Zeroize for ClaimValue {
    fn zeroize(&mut self) {
        match self {
            Self::Null => {}
            Self::Boolean(value) => value.zeroize(),
            Self::String(value) => value.zeroize(),
            Self::Signed(value) => value.zeroize(),
            Self::Unsigned(value) => value.zeroize(),
            Self::Decimal(value) => value.zeroize(),
            Self::Bytes(value) => value.zeroize(),
            Self::Date(value) => value.zeroize(),
            Self::DateTime(value) => value.zeroize(),
            Self::Array(values) => {
                for value in values {
                    value.zeroize();
                }
            }
            Self::Object(values) => {
                let entries = core::mem::take(values);
                for (mut key, mut value) in entries {
                    key.zeroize();
                    value.zeroize();
                }
            }
        }
    }
}

impl Zeroize for ClaimDecimal {
    fn zeroize(&mut self) {
        self.lexical.zeroize();
    }
}

impl Zeroize for ClaimDate {
    fn zeroize(&mut self) {
        self.iso8601.zeroize();
    }
}

impl Zeroize for ClaimDateTime {
    fn zeroize(&mut self) {
        self.rfc3339.zeroize();
    }
}

impl Drop for ClaimValue {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for ClaimValue {}

impl Drop for ClaimDecimal {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for ClaimDecimal {}

impl Drop for ClaimDate {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for ClaimDate {}

impl Drop for ClaimDateTime {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for ClaimDateTime {}

/// Validate fixed-point decimal spelling without exponents or non-finite forms.
pub fn validate_decimal(value: &str) -> Result<(), ClaimsError> {
    if value.is_empty() || value.len() > MAX_DECIMAL_BYTES {
        return Err(ClaimsError::InvalidInput(
            ClaimsInvalidReason::InvalidDecimal,
        ));
    }
    let bytes = value.as_bytes();
    let mut offset = 0usize;
    if bytes.first() == Some(&b'-') {
        offset = 1;
    }
    let integer_digits = count_digits(&bytes[offset..]);
    if integer_digits == 0 {
        return Err(ClaimsError::InvalidInput(
            ClaimsInvalidReason::InvalidDecimal,
        ));
    }
    let integer_end = offset
        .checked_add(integer_digits)
        .ok_or(ClaimsError::InvalidInput(
            ClaimsInvalidReason::ClaimValueLimitExceeded,
        ))?;
    let integer = &bytes[offset..integer_end];
    if integer.len() > 1 && integer.first() == Some(&b'0') {
        return Err(ClaimsError::InvalidInput(
            ClaimsInvalidReason::InvalidDecimal,
        ));
    }
    let decimal_index = integer_end;
    if decimal_index == bytes.len() {
        if bytes.first() == Some(&b'-') && integer == b"0" {
            return Err(ClaimsError::InvalidInput(
                ClaimsInvalidReason::InvalidDecimal,
            ));
        }
        return Ok(());
    }
    if bytes.get(decimal_index) != Some(&b'.') {
        return Err(ClaimsError::InvalidInput(
            ClaimsInvalidReason::InvalidDecimal,
        ));
    }
    let fraction_offset = decimal_index
        .checked_add(1)
        .ok_or(ClaimsError::InvalidInput(
            ClaimsInvalidReason::ClaimValueLimitExceeded,
        ))?;
    let fraction_digits = count_digits(&bytes[fraction_offset..]);
    if fraction_digits == 0 {
        return Err(ClaimsError::InvalidInput(
            ClaimsInvalidReason::InvalidDecimal,
        ));
    }
    let expected_len =
        fraction_offset
            .checked_add(fraction_digits)
            .ok_or(ClaimsError::InvalidInput(
                ClaimsInvalidReason::ClaimValueLimitExceeded,
            ))?;
    let fraction = &bytes[fraction_offset..expected_len];
    if fraction.last() == Some(&b'0') {
        return Err(ClaimsError::InvalidInput(
            ClaimsInvalidReason::InvalidDecimal,
        ));
    }
    if expected_len == bytes.len() {
        Ok(())
    } else {
        Err(ClaimsError::InvalidInput(
            ClaimsInvalidReason::InvalidDecimal,
        ))
    }
}

/// Validate an ISO 8601 calendar date.
pub fn validate_date(value: &str) -> Result<(), ClaimsError> {
    if value.len() != DATE_LEN {
        return Err(ClaimsError::InvalidInput(ClaimsInvalidReason::InvalidDate));
    }
    let bytes = value.as_bytes();
    if bytes.get(4) != Some(&b'-') || bytes.get(7) != Some(&b'-') {
        return Err(ClaimsError::InvalidInput(ClaimsInvalidReason::InvalidDate));
    }
    let year = parse_four_digits(bytes, 0)?;
    let month = parse_two_digits(bytes, 5)?;
    let day = parse_two_digits(bytes, 8)?;
    let month = Month::try_from(month)
        .map_err(|_| ClaimsError::InvalidInput(ClaimsInvalidReason::InvalidDate))?;
    Date::from_calendar_date(year, month, day)
        .map(|_| ())
        .map_err(|_| ClaimsError::InvalidInput(ClaimsInvalidReason::InvalidDate))
}

/// Validate an RFC 3339 date-time.
pub fn validate_date_time(value: &str) -> Result<(), ClaimsError> {
    OffsetDateTime::parse(value, &Rfc3339)
        .map(|_| ())
        .map_err(|_| ClaimsError::InvalidInput(ClaimsInvalidReason::InvalidDateTime))
}

/// Resolve a canonical path inside a normalized value.
pub fn resolve_claim_path<'a>(
    value: &'a ClaimValue,
    path: &ClaimPath,
) -> Result<Option<&'a ClaimValue>, ClaimsError> {
    let mut current = value;
    for segment in path.segments() {
        match (current, segment) {
            (ClaimValue::Object(values), ClaimPathSegment::Field(field)) => {
                let Some(next) = values.get(field) else {
                    return Ok(None);
                };
                current = next;
            }
            (ClaimValue::Array(values), ClaimPathSegment::ArrayIndex(index)) => {
                let index = usize::try_from(*index).map_err(|_| {
                    ClaimsError::InvalidInput(ClaimsInvalidReason::InvalidClaimPathSegment)
                })?;
                let Some(next) = values.get(index) else {
                    return Ok(None);
                };
                current = next;
            }
            _ => return Ok(None),
        }
    }
    Ok(Some(current))
}

pub(crate) fn validate_string_value(value: &str) -> Result<(), ClaimsError> {
    if value.len() > MAX_CLAIM_STRING_BYTES {
        return Err(ClaimsError::InvalidInput(
            ClaimsInvalidReason::ClaimValueLimitExceeded,
        ));
    }
    Ok(())
}

fn count_digits(bytes: &[u8]) -> usize {
    bytes
        .iter()
        .take_while(|byte| byte.is_ascii_digit())
        .count()
}

fn parse_four_digits(bytes: &[u8], offset: usize) -> Result<i32, ClaimsError> {
    let high = parse_two_digits(bytes, offset)?;
    let next_offset = offset
        .checked_add(2)
        .ok_or(ClaimsError::InvalidInput(ClaimsInvalidReason::InvalidDate))?;
    let low = parse_two_digits(bytes, next_offset)?;
    Ok(i32::from(high) * 100 + i32::from(low))
}

fn parse_two_digits(bytes: &[u8], offset: usize) -> Result<u8, ClaimsError> {
    let first = digit_at(bytes, offset)?;
    let next_offset = offset
        .checked_add(1)
        .ok_or(ClaimsError::InvalidInput(ClaimsInvalidReason::InvalidDate))?;
    let second = digit_at(bytes, next_offset)?;
    first
        .checked_mul(10)
        .and_then(|value| value.checked_add(second))
        .ok_or(ClaimsError::InvalidInput(ClaimsInvalidReason::InvalidDate))
}

fn digit_at(bytes: &[u8], offset: usize) -> Result<u8, ClaimsError> {
    let byte = bytes
        .get(offset)
        .ok_or(ClaimsError::InvalidInput(ClaimsInvalidReason::InvalidDate))?;
    if !byte.is_ascii_digit() {
        return Err(ClaimsError::InvalidInput(ClaimsInvalidReason::InvalidDate));
    }
    byte.checked_sub(b'0')
        .ok_or(ClaimsError::InvalidInput(ClaimsInvalidReason::InvalidDate))
}

fn redacted_len(len: usize) -> RedactedLen {
    RedactedLen { len }
}

struct RedactedLen {
    len: usize,
}

impl core::fmt::Debug for RedactedLen {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("redacted")
            .field("len", &self.len)
            .finish()
    }
}
