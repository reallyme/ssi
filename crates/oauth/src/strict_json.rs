// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Strict structural validation for security-sensitive JWT JSON.

use core::fmt;

use serde::de::{DeserializeSeed, MapAccess, SeqAccess, Visitor};
use zeroize::Zeroizing;

use crate::error::{OauthError, OauthResult, Reason};

const MAX_JWT_JSON_DEPTH: usize = 32;
const MAX_JWT_JSON_CONTAINER_ITEMS: usize = 256;

/// Rejects ambiguous JSON before it reaches a typed deserializer.
///
/// RFC 8259 §4 only says object names SHOULD be unique, and implementations
/// disagree about which duplicate value wins. RFC 8725 §2.6 requires avoiding
/// such multi-parser ambiguity for JWTs, so every object level is checked.
pub(crate) fn validate_strict_json(input: &[u8]) -> OauthResult<()> {
    let mut deserializer = serde_json::Deserializer::from_slice(input);
    StrictJsonSeed { depth: 0 }
        .deserialize(&mut deserializer)
        .map_err(|_| OauthError::new(Reason::InvalidJson))?;
    deserializer
        .end()
        .map_err(|_| OauthError::new(Reason::InvalidJson))
}

struct StrictJsonSeed {
    depth: usize,
}

impl<'de> DeserializeSeed<'de> for StrictJsonSeed {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(StrictJsonVisitor { depth: self.depth })
    }
}

struct StrictJsonVisitor {
    depth: usize,
}

impl StrictJsonVisitor {
    fn next_depth<E>(&self) -> Result<usize, E>
    where
        E: serde::de::Error,
    {
        let next = self
            .depth
            .checked_add(1)
            .ok_or_else(|| E::custom("JWT JSON rejected"))?;
        if next > MAX_JWT_JSON_DEPTH {
            return Err(E::custom("JWT JSON rejected"));
        }
        Ok(next)
    }
}

impl<'de> Visitor<'de> for StrictJsonVisitor {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("bounded unambiguous JWT JSON")
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_bool<E>(self, _value: bool) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_i64<E>(self, _value: i64) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_u64<E>(self, _value: u64) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_f64<E>(self, _value: f64) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_str<E>(self, _value: &str) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_string<E>(self, mut value: String) -> Result<Self::Value, E> {
        zeroize::Zeroize::zeroize(&mut value);
        Ok(())
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let next_depth = self.next_depth::<A::Error>()?;
        let mut count = 0usize;
        while sequence
            .next_element_seed(StrictJsonSeed { depth: next_depth })?
            .is_some()
        {
            count = count
                .checked_add(1)
                .ok_or_else(|| serde::de::Error::custom("JWT JSON rejected"))?;
            if count > MAX_JWT_JSON_CONTAINER_ITEMS {
                return Err(serde::de::Error::custom("JWT JSON rejected"));
            }
        }
        Ok(())
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let next_depth = self.next_depth::<A::Error>()?;
        let mut keys: Vec<Zeroizing<String>> = Vec::new();
        while let Some(key) = map.next_key::<String>()? {
            let key = Zeroizing::new(key);
            if keys
                .iter()
                .any(|existing| existing.as_str() == key.as_str())
            {
                return Err(serde::de::Error::custom("JWT JSON rejected"));
            }
            if keys.len() >= MAX_JWT_JSON_CONTAINER_ITEMS {
                return Err(serde::de::Error::custom("JWT JSON rejected"));
            }
            keys.push(key);
            map.next_value_seed(StrictJsonSeed { depth: next_depth })?;
        }
        Ok(())
    }
}
