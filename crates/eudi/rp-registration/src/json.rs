// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::de::{DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::{RegistrationError, RegistrationErrorReason};

pub(crate) const MAX_JSON_BYTES: usize = 4 * 1_024 * 1_024;
pub(crate) const MAX_JSON_DEPTH: usize = 24;
pub(crate) const MAX_JSON_ITEMS: usize = 1_024;
pub(crate) const MAX_JSON_MEMBERS: usize = 256;
pub(crate) const MAX_JSON_STRING_BYTES: usize = 16_384;

thread_local! {
    static PARSE_REASON: Cell<Option<RegistrationErrorReason>> = const { Cell::new(None) };
}

#[derive(Deserialize, Serialize)]
#[serde(untagged)]
pub(crate) enum StrictValue {
    Null,
    Bool(bool),
    Number(serde_json::Number),
    String(String),
    Array(Vec<StrictValue>),
    Object(BTreeMap<String, StrictValue>),
}

impl Zeroize for StrictValue {
    fn zeroize(&mut self) {
        match self {
            Self::Null => {}
            Self::Bool(value) => value.zeroize(),
            Self::Number(value) => *value = 0_u64.into(),
            Self::String(value) => value.zeroize(),
            Self::Array(values) => values.zeroize(),
            Self::Object(values) => {
                let owned = core::mem::take(values);
                for (mut key, mut value) in owned {
                    key.zeroize();
                    value.zeroize();
                }
            }
        }
    }
}

impl Drop for StrictValue {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl StrictValue {
    pub(crate) fn take_array(&mut self) -> Option<Vec<Self>> {
        match self {
            Self::Array(values) => Some(core::mem::take(values)),
            _ => None,
        }
    }

    pub(crate) fn take_object(&mut self) -> Option<BTreeMap<String, Self>> {
        match self {
            Self::Object(values) => Some(core::mem::take(values)),
            _ => None,
        }
    }

    pub(crate) fn take_string(&mut self) -> Option<String> {
        match self {
            Self::String(value) => Some(core::mem::take(value)),
            _ => None,
        }
    }
}

pub(crate) fn parse_strict(input: &[u8]) -> Result<StrictValue, RegistrationError> {
    if input.is_empty() {
        return Err(RegistrationError::from_reason(
            RegistrationErrorReason::EmptyInput,
        ));
    }
    if input.len() > MAX_JSON_BYTES {
        return Err(RegistrationError::from_reason(
            RegistrationErrorReason::InputTooLarge,
        ));
    }
    PARSE_REASON.with(|reason| reason.set(None));
    let mut deserializer = serde_json::Deserializer::from_slice(input);
    let value = ValueSeed { depth: 0 }
        .deserialize(&mut deserializer)
        .map_err(|_error| parse_error())?;
    deserializer.end().map_err(|_error| parse_error())?;
    Ok(value)
}

/// Deserializes a closed schema only after the exact input bytes passed the
/// bounded duplicate-member and resource-limit validation of [`parse_strict`].
///
/// The typed decode reads the original bytes directly. Because the strict
/// pass already rejected duplicate members, oversized strings, excessive
/// depth, and oversized collections, this is equivalent to decoding a
/// re-serialized copy of the validated tree without the extra allocation.
pub(crate) fn deserialize_strict<T>(input: &[u8]) -> Result<T, RegistrationError>
where
    T: for<'de> Deserialize<'de>,
{
    drop(parse_strict(input)?);
    serde_json::from_slice(input)
        .map_err(|_error| RegistrationError::from_reason(RegistrationErrorReason::InvalidField))
}

pub(crate) fn canonical_json<T>(value: &T) -> Result<Vec<u8>, RegistrationError>
where
    T: Serialize,
{
    let encoded = zeroize::Zeroizing::new(serde_json::to_vec(value).map_err(|_error| {
        RegistrationError::from_reason(RegistrationErrorReason::SerializationFailed)
    })?);
    let text = core::str::from_utf8(&encoded).map_err(|_error| {
        RegistrationError::from_reason(RegistrationErrorReason::SerializationFailed)
    })?;
    let mut canonical =
        zeroize::Zeroizing::new(reallyme_codec::jcs::canonicalize_json_text(text).map_err(
            |_error| RegistrationError::from_reason(RegistrationErrorReason::SerializationFailed),
        )?);
    Ok(core::mem::take(&mut *canonical).into_bytes())
}

fn parse_error() -> RegistrationError {
    RegistrationError::from_reason(PARSE_REASON.with(|reason| {
        reason
            .take()
            .unwrap_or(RegistrationErrorReason::InvalidJson)
    }))
}

fn fail<E>(reason: RegistrationErrorReason) -> E
where
    E: serde::de::Error,
{
    PARSE_REASON.with(|slot| slot.set(Some(reason)));
    E::custom("invalid bounded EUDI JSON")
}

fn next_depth<E>(depth: usize) -> Result<usize, E>
where
    E: serde::de::Error,
{
    let next = depth
        .checked_add(1)
        .ok_or_else(|| fail::<E>(RegistrationErrorReason::ResourceLimitExceeded))?;
    if next > MAX_JSON_DEPTH {
        return Err(fail(RegistrationErrorReason::ResourceLimitExceeded));
    }
    Ok(next)
}

struct ValueSeed {
    depth: usize,
}

impl<'de> DeserializeSeed<'de> for ValueSeed {
    type Value = StrictValue;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(ValueVisitor { depth: self.depth })
    }
}

struct ValueVisitor {
    depth: usize,
}

impl<'de> Visitor<'de> for ValueVisitor {
    type Value = StrictValue;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("bounded JSON")
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(StrictValue::Null)
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(StrictValue::Null)
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(StrictValue::Bool(value))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(StrictValue::Number(value.into()))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(StrictValue::Number(value.into()))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        serde_json::Number::from_f64(value)
            .map(StrictValue::Number)
            .ok_or_else(|| fail(RegistrationErrorReason::InvalidJson))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        validate_string::<E>(value)?;
        Ok(StrictValue::String(value.to_owned()))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        validate_string::<E>(&value)?;
        Ok(StrictValue::String(value))
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let depth = next_depth(self.depth)?;
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element_seed(ValueSeed { depth })? {
            if values.len() >= MAX_JSON_ITEMS {
                return Err(fail(RegistrationErrorReason::ResourceLimitExceeded));
            }
            values.push(value);
        }
        Ok(StrictValue::Array(values))
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let depth = next_depth(self.depth)?;
        let mut names = BTreeSet::new();
        let mut values = BTreeMap::new();
        while let Some(name) = map.next_key::<String>()? {
            validate_string::<A::Error>(&name)?;
            if values.len() >= MAX_JSON_MEMBERS {
                return Err(fail(RegistrationErrorReason::ResourceLimitExceeded));
            }
            if !names.insert(name.clone()) {
                return Err(fail(RegistrationErrorReason::DuplicateJsonMember));
            }
            let value = map.next_value_seed(ValueSeed { depth })?;
            values.insert(name, value);
        }
        Ok(StrictValue::Object(values))
    }
}

fn validate_string<E>(value: &str) -> Result<(), E>
where
    E: serde::de::Error,
{
    if value.len() > MAX_JSON_STRING_BYTES || value.bytes().any(|byte| byte == 0) {
        return Err(fail(RegistrationErrorReason::ResourceLimitExceeded));
    }
    Ok(())
}
