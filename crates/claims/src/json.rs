// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::{
    ClaimDecimal, ClaimValue, ClaimsError, ClaimsInvalidReason, MAX_CLAIM_ARRAY_ITEMS,
    MAX_CLAIM_OBJECT_PROPERTIES, MAX_CLAIM_VALUE_DEPTH,
};
use serde::de::{DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde_json::Value as JsonValue;
use std::cell::Cell;
use std::collections::BTreeMap;
use std::fmt;

thread_local! {
    static JSON_PARSE_REASON: Cell<Option<ClaimsInvalidReason>> = const { Cell::new(None) };
}

/// Normalize an already-parsed JSON value into the protocol-neutral model.
///
/// Prefer `claim_value_from_json_slice` when JSON bytes are the original
/// external boundary, because `serde_json::Value` cannot preserve duplicate
/// object members.
pub fn claim_value_from_json(value: &JsonValue) -> Result<ClaimValue, ClaimsError> {
    claim_value_from_json_at_depth(value, 0)
}

/// Normalize a JSON claim payload while detecting duplicate object members.
///
/// This parser is intended for external JSON boundaries. `serde_json::Value`
/// cannot represent duplicate object members, so this entry point should be
/// used when JSON bytes are the original wire input and duplicate claim names
/// must fail closed before semantic validation.
pub fn claim_value_from_json_slice(input: &[u8]) -> Result<ClaimValue, ClaimsError> {
    JSON_PARSE_REASON.with(|reason| reason.set(None));
    let mut deserializer = serde_json::Deserializer::from_slice(input);
    let value = ClaimValueSeed { depth: 0 }
        .deserialize(&mut deserializer)
        .map_err(|_| {
            ClaimsError::InvalidInput(JSON_PARSE_REASON.with(|reason| {
                reason
                    .take()
                    .unwrap_or(ClaimsInvalidReason::InvalidClaimPayloadJson)
            }))
        })?;
    deserializer.end().map_err(|_| {
        ClaimsError::InvalidInput(JSON_PARSE_REASON.with(|reason| {
            reason
                .take()
                .unwrap_or(ClaimsInvalidReason::InvalidClaimPayloadJson)
        }))
    })?;
    Ok(value)
}

fn claim_value_from_json_at_depth(
    value: &JsonValue,
    depth: usize,
) -> Result<ClaimValue, ClaimsError> {
    if depth > MAX_CLAIM_VALUE_DEPTH {
        return Err(ClaimsError::InvalidInput(
            ClaimsInvalidReason::ClaimValueLimitExceeded,
        ));
    }
    match value {
        JsonValue::Null => Ok(ClaimValue::Null),
        JsonValue::Bool(value) => Ok(ClaimValue::Boolean(*value)),
        JsonValue::String(value) => {
            crate::values::validate_string_value(value.as_str())?;
            Ok(ClaimValue::String(value.clone()))
        }
        JsonValue::Number(value) => normalize_json_number(value),
        JsonValue::Array(values) => {
            if values.len() > MAX_CLAIM_ARRAY_ITEMS {
                return Err(ClaimsError::InvalidInput(
                    ClaimsInvalidReason::ClaimValueLimitExceeded,
                ));
            }
            let next_depth = checked_next_depth(depth)?;
            let mut out = Vec::with_capacity(values.len());
            for value in values {
                out.push(claim_value_from_json_at_depth(value, next_depth)?);
            }
            Ok(ClaimValue::Array(out))
        }
        JsonValue::Object(values) => {
            if values.len() > MAX_CLAIM_OBJECT_PROPERTIES {
                return Err(ClaimsError::InvalidInput(
                    ClaimsInvalidReason::ClaimValueLimitExceeded,
                ));
            }
            let next_depth = checked_next_depth(depth)?;
            let mut out = BTreeMap::new();
            for (key, value) in values {
                validate_claim_object_key(key.as_str())?;
                crate::values::validate_string_value(key.as_str())?;
                out.insert(
                    key.clone(),
                    claim_value_from_json_at_depth(value, next_depth)?,
                );
            }
            Ok(ClaimValue::Object(out))
        }
    }
}

fn normalize_json_number(value: &serde_json::Number) -> Result<ClaimValue, ClaimsError> {
    if let Some(value) = value.as_u64() {
        return Ok(ClaimValue::Unsigned(value));
    }
    if let Some(value) = value.as_i64() {
        return Ok(ClaimValue::Signed(value));
    }
    let Some(value) = value.as_f64() else {
        return Err(ClaimsError::InvalidInput(
            ClaimsInvalidReason::InvalidDecimal,
        ));
    };
    decimal_from_json_f64(value)
}

/// Maximum significant decimal digits that survive a round trip through an
/// IEEE 754 binary64 value unchanged (`DBL_DIG`).
const MAX_EXACT_JSON_DECIMAL_SIGNIFICANT_DIGITS: usize = 15;

/// Convert a JSON non-integer number into a canonical fixed-point decimal.
///
/// This is the single decimal normalization path for both JSON entry points.
/// JSON numbers reach this layer as binary64 values, so the original lexical
/// form is no longer available. The shortest round-trip fixed-point rendering
/// is accepted only when it has at most
/// [`MAX_EXACT_JSON_DECIMAL_SIGNIFICANT_DIGITS`] significant digits, which is
/// the range where every decimal input maps back to itself exactly. Longer
/// renderings may differ from the submitted number and fail closed.
fn decimal_from_json_f64(value: f64) -> Result<ClaimValue, ClaimsError> {
    if !value.is_finite() {
        return Err(ClaimsError::InvalidInput(
            ClaimsInvalidReason::InvalidDecimal,
        ));
    }
    let lexical = value.to_string();
    if significant_digit_count(lexical.as_str()) > MAX_EXACT_JSON_DECIMAL_SIGNIFICANT_DIGITS {
        return Err(ClaimsError::InvalidInput(
            ClaimsInvalidReason::InvalidDecimal,
        ));
    }
    ClaimDecimal::new(lexical).map(ClaimValue::Decimal)
}

fn significant_digit_count(lexical: &str) -> usize {
    let digits = lexical
        .bytes()
        .filter(u8::is_ascii_digit)
        .skip_while(|digit| *digit == b'0');
    let mut count = 0_usize;
    let mut pending_zeros = 0_usize;
    for digit in digits {
        if digit == b'0' {
            pending_zeros = pending_zeros.saturating_add(1);
        } else {
            count = count.saturating_add(pending_zeros).saturating_add(1);
            pending_zeros = 0;
        }
    }
    count
}

fn validate_claim_object_key(value: &str) -> Result<(), ClaimsError> {
    if !value.is_ascii() {
        return Err(ClaimsError::InvalidInput(
            ClaimsInvalidReason::ConfusableClaimName,
        ));
    }
    if value.is_empty() || value.bytes().any(|byte| byte.is_ascii_control()) {
        return Err(ClaimsError::InvalidInput(
            ClaimsInvalidReason::InvalidClaimPathSegment,
        ));
    }
    Ok(())
}

struct ClaimValueSeed {
    depth: usize,
}

impl<'de> DeserializeSeed<'de> for ClaimValueSeed {
    type Value = ClaimValue;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(ClaimValueVisitor { depth: self.depth })
    }
}

struct ClaimValueVisitor {
    depth: usize,
}

impl<'de> Visitor<'de> for ClaimValueVisitor {
    type Value = ClaimValue;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a bounded credential claim JSON value")
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(ClaimValue::Null)
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(ClaimValue::Boolean(value))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(ClaimValue::Signed(value))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(ClaimValue::Unsigned(value))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        decimal_from_json_f64(value)
            .map_err(|_| json_parse_error::<E>(ClaimsInvalidReason::InvalidDecimal))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        crate::values::validate_string_value(value)
            .map_err(|_| json_parse_error::<E>(ClaimsInvalidReason::ClaimValueLimitExceeded))?;
        Ok(ClaimValue::String(value.to_owned()))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        crate::values::validate_string_value(value.as_str())
            .map_err(|_| json_parse_error::<E>(ClaimsInvalidReason::ClaimValueLimitExceeded))?;
        Ok(ClaimValue::String(value))
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let next_depth = checked_next_depth(self.depth).map_err(|_| {
            json_parse_error::<A::Error>(ClaimsInvalidReason::ClaimValueLimitExceeded)
        })?;
        let mut out = Vec::new();
        while let Some(value) = seq.next_element_seed(ClaimValueSeed { depth: next_depth })? {
            if out.len() >= MAX_CLAIM_ARRAY_ITEMS {
                return Err(json_parse_error::<A::Error>(
                    ClaimsInvalidReason::ClaimValueLimitExceeded,
                ));
            }
            out.push(value);
        }
        Ok(ClaimValue::Array(out))
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let next_depth = checked_next_depth(self.depth).map_err(|_| {
            json_parse_error::<A::Error>(ClaimsInvalidReason::ClaimValueLimitExceeded)
        })?;
        let mut out = BTreeMap::new();
        while let Some(key) = map.next_key::<String>()? {
            validate_claim_object_key(key.as_str()).map_err(|error| {
                let ClaimsError::InvalidInput(reason) = error else {
                    return json_parse_error::<A::Error>(
                        ClaimsInvalidReason::InvalidClaimPayloadJson,
                    );
                };
                json_parse_error::<A::Error>(reason)
            })?;
            crate::values::validate_string_value(key.as_str()).map_err(|_| {
                json_parse_error::<A::Error>(ClaimsInvalidReason::ClaimValueLimitExceeded)
            })?;
            let value = map.next_value_seed(ClaimValueSeed { depth: next_depth })?;
            if out.insert(key, value).is_some() {
                return Err(json_parse_error::<A::Error>(
                    ClaimsInvalidReason::DuplicateClaimName,
                ));
            }
            if out.len() > MAX_CLAIM_OBJECT_PROPERTIES {
                return Err(json_parse_error::<A::Error>(
                    ClaimsInvalidReason::ClaimValueLimitExceeded,
                ));
            }
        }
        Ok(ClaimValue::Object(out))
    }
}

fn json_parse_error<E>(reason: ClaimsInvalidReason) -> E
where
    E: serde::de::Error,
{
    JSON_PARSE_REASON.with(|stored| stored.set(Some(reason)));
    E::custom("claim payload rejected")
}

fn checked_next_depth(depth: usize) -> Result<usize, ClaimsError> {
    let next_depth = depth.checked_add(1).ok_or(ClaimsError::InvalidInput(
        ClaimsInvalidReason::ClaimValueLimitExceeded,
    ))?;
    if next_depth > MAX_CLAIM_VALUE_DEPTH {
        return Err(ClaimsError::InvalidInput(
            ClaimsInvalidReason::ClaimValueLimitExceeded,
        ));
    }
    Ok(next_depth)
}
