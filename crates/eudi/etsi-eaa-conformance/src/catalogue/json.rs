// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Bounded, duplicate-rejecting JSON parser for catalogue wire documents.

use core::fmt;
use core::ops::{Deref, DerefMut};
use std::cell::Cell;
use std::collections::BTreeMap;

use serde::de::{DeserializeSeed, MapAccess, SeqAccess, Visitor};
use zeroize::Zeroize;

use super::{CatalogueError, CatalogueErrorReason};

const MAX_CATALOGUE_JSON_BYTES: usize = 1_048_576;
const MAX_CATALOGUE_DEPTH: usize = 16;
const MAX_ARRAY_ITEMS: usize = 1_024;
const MAX_OBJECT_MEMBERS: usize = 64;
const MAX_STRING_BYTES: usize = 8_192;

thread_local! {
    static PARSE_REASON: Cell<Option<CatalogueErrorReason>> = const { Cell::new(None) };
}

pub(super) enum StrictValue {
    Null,
    Bool(bool),
    Number(serde_json::Number),
    String(String),
    Array(Vec<StrictValue>),
    Object(StrictObject),
}

#[derive(Default)]
pub(super) struct StrictObject(BTreeMap<String, StrictValue>);

impl Deref for StrictObject {
    type Target = BTreeMap<String, StrictValue>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for StrictObject {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Zeroize for StrictObject {
    fn zeroize(&mut self) {
        let owned = core::mem::take(&mut self.0);
        for (mut key, mut value) in owned {
            key.zeroize();
            value.zeroize();
        }
    }
}

impl Drop for StrictObject {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl Zeroize for StrictValue {
    fn zeroize(&mut self) {
        match self {
            Self::Null => {}
            Self::Bool(value) => value.zeroize(),
            Self::Number(value) => *value = 0_u64.into(),
            Self::String(value) => value.zeroize(),
            Self::Array(values) => values.zeroize(),
            Self::Object(values) => values.zeroize(),
        }
    }
}

impl Drop for StrictValue {
    fn drop(&mut self) {
        self.zeroize();
    }
}

pub(super) fn parse_strict(input: &[u8]) -> Result<StrictValue, CatalogueError> {
    if input.is_empty() {
        return Err(CatalogueError::new(CatalogueErrorReason::EmptyInput));
    }
    if input.len() > MAX_CATALOGUE_JSON_BYTES {
        return Err(CatalogueError::new(
            CatalogueErrorReason::ResourceLimitExceeded,
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

fn parse_error() -> CatalogueError {
    CatalogueError::new(
        PARSE_REASON.with(|reason| reason.take().unwrap_or(CatalogueErrorReason::InvalidJson)),
    )
}

fn fail<E>(reason: CatalogueErrorReason) -> E
where
    E: serde::de::Error,
{
    PARSE_REASON.with(|slot| slot.set(Some(reason)));
    E::custom("invalid bounded EUDI catalogue JSON")
}

fn next_depth<E>(depth: usize) -> Result<usize, E>
where
    E: serde::de::Error,
{
    let next = depth
        .checked_add(1)
        .ok_or_else(|| fail::<E>(CatalogueErrorReason::ResourceLimitExceeded))?;
    if next > MAX_CATALOGUE_DEPTH {
        return Err(fail(CatalogueErrorReason::ResourceLimitExceeded));
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
        formatter.write_str("bounded EUDI catalogue JSON")
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
            .ok_or_else(|| fail(CatalogueErrorReason::InvalidJson))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        validate_string::<E>(value)?;
        Ok(StrictValue::String(value.to_owned()))
    }

    fn visit_string<E>(self, mut value: String) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        if let Err(error) = validate_string::<E>(&value) {
            value.zeroize();
            return Err(error);
        }
        Ok(StrictValue::String(value))
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let depth = next_depth(self.depth)?;
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element_seed(ValueSeed { depth })? {
            if values.len() >= MAX_ARRAY_ITEMS {
                return Err(fail(CatalogueErrorReason::ResourceLimitExceeded));
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
        let mut values = StrictObject::default();
        while let Some(mut name) = map.next_key::<String>()? {
            if let Err(error) = validate_string::<A::Error>(&name) {
                name.zeroize();
                return Err(error);
            }
            if values.len() >= MAX_OBJECT_MEMBERS {
                name.zeroize();
                return Err(fail(CatalogueErrorReason::ResourceLimitExceeded));
            }
            // Avoid retaining a second copy of an untrusted member name: the
            // map owns the only copy and `StrictValue::drop` scrubs it.
            if values.contains_key(&name) {
                name.zeroize();
                return Err(fail(CatalogueErrorReason::DuplicateJsonMember));
            }
            let value = match map.next_value_seed(ValueSeed { depth }) {
                Ok(value) => value,
                Err(error) => {
                    name.zeroize();
                    return Err(error);
                }
            };
            values.insert(name, value);
        }
        Ok(StrictValue::Object(values))
    }
}

fn validate_string<E>(value: &str) -> Result<(), E>
where
    E: serde::de::Error,
{
    if value.len() > MAX_STRING_BYTES || value.bytes().any(|byte| byte == 0) {
        return Err(fail(CatalogueErrorReason::ResourceLimitExceeded));
    }
    Ok(())
}
