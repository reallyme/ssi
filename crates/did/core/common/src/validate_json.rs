// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Validate untrusted JSON before a last-member-wins value parser can erase ambiguity.

use core::fmt;
use std::collections::BTreeSet;

use serde::de::{DeserializeSeed, MapAccess, SeqAccess, Visitor};
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

const MAX_BYTES: usize = 1_048_576;
const MAX_DEPTH: usize = 32;
const MAX_NODES: usize = 16_384;

/// Stable reason for rejecting a JSON boundary input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JsonBoundaryErrorReason {
    /// Invalid JSON, duplicate decoded member names, or excessive nesting/work.
    InvalidDocument,
}

/// Sanitized JSON boundary error; parser diagnostics never leave this module.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("invalid bounded JSON document")]
pub struct JsonBoundaryError {
    /// Domain-specific failure reason.
    pub reason: JsonBoundaryErrorReason,
}

/// Reject duplicate names at every nesting level, trailing input, and resource abuse.
///
/// This preflight retains only object names. Scalar contents remain borrowed, and
/// allocated names are scrubbed on every return path, including parser failure.
pub fn validate_json(bytes: &[u8]) -> Result<(), JsonBoundaryError> {
    let invalid = || JsonBoundaryError {
        reason: JsonBoundaryErrorReason::InvalidDocument,
    };
    if bytes.is_empty() || bytes.len() > MAX_BYTES {
        return Err(invalid());
    }
    let mut nodes = MAX_NODES;
    let mut parser = serde_json::Deserializer::from_slice(bytes);
    Scan {
        depth: 0,
        remaining: &mut nodes,
    }
    .deserialize(&mut parser)
    .map_err(|_| invalid())?;
    parser.end().map_err(|_| invalid())
}

#[derive(PartialEq, Eq, PartialOrd, Ord, Zeroize, ZeroizeOnDrop)]
struct MemberName(String);

struct Scan<'a> {
    depth: usize,
    remaining: &'a mut usize,
}

impl<'de> DeserializeSeed<'de> for Scan<'_> {
    type Value = ();

    fn deserialize<D: serde::Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        *self.remaining = self
            .remaining
            .checked_sub(1)
            .ok_or_else(|| serde::de::Error::custom("JSON resource limit"))?;
        if self.depth > MAX_DEPTH {
            return Err(serde::de::Error::custom("JSON resource limit"));
        }
        deserializer.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for Scan<'_> {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("bounded unambiguous JSON")
    }

    fn visit_unit<E>(self) -> Result<(), E> {
        Ok(())
    }
    fn visit_bool<E>(self, _: bool) -> Result<(), E> {
        Ok(())
    }
    fn visit_i64<E>(self, _: i64) -> Result<(), E> {
        Ok(())
    }
    fn visit_u64<E>(self, _: u64) -> Result<(), E> {
        Ok(())
    }
    fn visit_f64<E>(self, _: f64) -> Result<(), E> {
        Ok(())
    }
    fn visit_str<E>(self, _: &str) -> Result<(), E> {
        Ok(())
    }
    fn visit_string<E>(self, mut value: String) -> Result<(), E> {
        value.zeroize();
        Ok(())
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<(), A::Error> {
        let depth = self
            .depth
            .checked_add(1)
            .ok_or_else(|| serde::de::Error::custom("JSON resource limit"))?;
        while sequence
            .next_element_seed(Scan {
                depth,
                remaining: self.remaining,
            })?
            .is_some()
        {}
        Ok(())
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
        let depth = self
            .depth
            .checked_add(1)
            .ok_or_else(|| serde::de::Error::custom("JSON resource limit"))?;
        let mut names = BTreeSet::new();
        while let Some(name) = map.next_key::<String>()? {
            if !names.insert(MemberName(name)) {
                return Err(serde::de::Error::custom("duplicate JSON member"));
            }
            map.next_value_seed(Scan {
                depth,
                remaining: self.remaining,
            })?;
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "validate_json_tests.rs"]
mod tests;
