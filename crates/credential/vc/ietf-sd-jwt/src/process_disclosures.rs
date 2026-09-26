// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Bounded RFC 9901 disclosure processing shared by every SD-JWT verifier in
//! this crate.
//!
//! Processing follows RFC 9901 §7.1: every digest must be unique across the
//! issuer payload and all disclosures, each disclosure must be referenced
//! exactly once by a digest of the matching kind, `_sd_alg` may appear only
//! at the payload root, and `...` may appear only as an array-element
//! placeholder. Recursion depth and visited node counts are bounded so hostile
//! nesting fails closed with a typed error instead of exhausting the stack.

use std::collections::{BTreeMap, BTreeSet};

use codec_base64url::base64url_to_bytes;
use serde_json::{Map, Value};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::error::IetfSdJwtVcError;
use crate::issue::parse_sd_alg;
use crate::registered_claims::{is_non_selectively_disclosable_claim, SD_JWT_STRUCTURAL_CLAIMS};
use crate::sensitive::{
    zeroize_json_value, MAX_SD_JWT_DISCLOSURES, MAX_SD_JWT_DISCLOSURE_BYTES, MAX_SD_JWT_JSON_DEPTH,
    MAX_SD_JWT_JSON_NODES,
};

const SD_CLAIM_NAME: &str = "_sd";
const SD_ALG_CLAIM_NAME: &str = "_sd_alg";
const ARRAY_DIGEST_CLAIM_NAME: &str = "...";
const OBJECT_DISCLOSURE_ELEMENTS: usize = 3;
const ARRAY_DISCLOSURE_ELEMENTS: usize = 2;
/// Upper bound on the salt string carried by one disclosure.
const MAX_DISCLOSURE_SALT_BYTES: usize = 256;

/// Content of one decoded disclosure.
pub(crate) enum DisclosureContent {
    ObjectProperty { name: String, value: Value },
    ArrayElement { value: Value },
}

impl Zeroize for DisclosureContent {
    fn zeroize(&mut self) {
        match self {
            Self::ObjectProperty { name, value } => {
                name.zeroize();
                zeroize_json_value(value);
            }
            Self::ArrayElement { value } => zeroize_json_value(value),
        }
    }
}

impl Drop for DisclosureContent {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for DisclosureContent {}

/// One authenticated disclosure, kept in original serialization order.
pub(crate) struct DecodedDisclosure {
    pub(crate) salt: String,
    pub(crate) content: DisclosureContent,
}

impl DecodedDisclosure {
    /// Rebuild the disclosure JSON array without re-reading the encoded form.
    pub(crate) fn to_json_array(&self) -> Value {
        match &self.content {
            DisclosureContent::ObjectProperty { name, value } => Value::Array(vec![
                Value::String(self.salt.clone()),
                Value::String(name.clone()),
                value.clone(),
            ]),
            DisclosureContent::ArrayElement { value } => {
                Value::Array(vec![Value::String(self.salt.clone()), value.clone()])
            }
        }
    }
}

impl Zeroize for DecodedDisclosure {
    fn zeroize(&mut self) {
        self.salt.zeroize();
        self.content.zeroize();
    }
}

impl Drop for DecodedDisclosure {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for DecodedDisclosure {}

/// Resolved payload together with the disclosures that produced it.
pub(crate) struct ProcessedSdJwt {
    pub(crate) resolved: Value,
    pub(crate) disclosures: Vec<DecodedDisclosure>,
}

impl Zeroize for ProcessedSdJwt {
    fn zeroize(&mut self) {
        zeroize_json_value(&mut self.resolved);
        for disclosure in &mut self.disclosures {
            disclosure.zeroize();
        }
        self.disclosures.clear();
    }
}

impl Drop for ProcessedSdJwt {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for ProcessedSdJwt {}

/// Structural position of a JSON value inside an SD-JWT payload.
#[derive(Clone, Copy, PartialEq, Eq)]
enum ValuePosition {
    Root,
    ArrayElement,
    Nested,
}

/// Shared depth and node budget for one processing run.
struct Budget {
    nodes: usize,
}

impl Budget {
    fn visit(&mut self, depth: usize) -> Result<(), IetfSdJwtVcError> {
        if depth > MAX_SD_JWT_JSON_DEPTH {
            return Err(IetfSdJwtVcError::ProcessingLimitExceeded);
        }
        self.nodes = self
            .nodes
            .checked_add(1)
            .ok_or(IetfSdJwtVcError::ProcessingLimitExceeded)?;
        if self.nodes > MAX_SD_JWT_JSON_NODES {
            return Err(IetfSdJwtVcError::ProcessingLimitExceeded);
        }
        Ok(())
    }
}

fn next_depth(depth: usize) -> Result<usize, IetfSdJwtVcError> {
    depth
        .checked_add(1)
        .ok_or(IetfSdJwtVcError::ProcessingLimitExceeded)
}

/// Validate, match, and resolve disclosures against an issuer payload.
pub(crate) fn process_sd_jwt_disclosures(
    payload: &Value,
    encoded_disclosures: &[String],
) -> Result<ProcessedSdJwt, IetfSdJwtVcError> {
    let root = payload.as_object().ok_or(IetfSdJwtVcError::InvalidInput)?;
    let hash_algorithm = parse_sd_alg(root)?;
    if encoded_disclosures.len() > MAX_SD_JWT_DISCLOSURES {
        return Err(IetfSdJwtVcError::InvalidCompactFormat);
    }

    let mut budget = Budget { nodes: 0 };
    let mut expected = BTreeSet::new();
    collect_digests(payload, ValuePosition::Root, 0, &mut budget, &mut expected)?;
    if expected.is_empty() && !encoded_disclosures.is_empty() {
        return Err(IetfSdJwtVcError::MissingSdClaim);
    }

    let mut decoded = Vec::with_capacity(encoded_disclosures.len());
    let mut digest_index = BTreeMap::new();
    for (index, encoded) in encoded_disclosures.iter().enumerate() {
        let digest = hash_algorithm.digest_b64url(encoded);
        if digest_index.insert(digest, index).is_some() {
            return Err(IetfSdJwtVcError::InvalidDisclosure);
        }
        decoded.push(decode_disclosure(encoded)?);
    }

    let mut accepted = vec![false; decoded.len()];
    let mut progress = true;
    while progress {
        progress = false;
        for (digest, &index) in &digest_index {
            let already_accepted = accepted
                .get(index)
                .copied()
                .ok_or(IetfSdJwtVcError::InvalidDisclosure)?;
            if already_accepted || !expected.contains(digest) {
                continue;
            }
            let disclosure = decoded
                .get(index)
                .ok_or(IetfSdJwtVcError::InvalidDisclosure)?;
            let value = match &disclosure.content {
                DisclosureContent::ObjectProperty { value, .. }
                | DisclosureContent::ArrayElement { value } => value,
            };
            let mut nested = BTreeSet::new();
            collect_digests(value, ValuePosition::Nested, 0, &mut budget, &mut nested)?;
            for nested_digest in nested {
                if !expected.insert(nested_digest) {
                    return Err(IetfSdJwtVcError::InvalidSdClaim);
                }
            }
            if let Some(flag) = accepted.get_mut(index) {
                *flag = true;
            }
            progress = true;
        }
    }
    if accepted.iter().any(|flag| !flag) {
        return Err(IetfSdJwtVcError::DisclosureDigestMismatch);
    }

    let mut resolver = Resolver {
        disclosures: &decoded,
        digest_index: &digest_index,
        budget: Budget { nodes: 0 },
    };
    let resolved = resolver.resolve(payload, ValuePosition::Root, 0)?;
    Ok(ProcessedSdJwt {
        resolved,
        disclosures: decoded,
    })
}

fn decode_disclosure(encoded: &str) -> Result<DecodedDisclosure, IetfSdJwtVcError> {
    if encoded.is_empty() || encoded.len() > MAX_SD_JWT_DISCLOSURE_BYTES {
        return Err(IetfSdJwtVcError::InvalidDisclosure);
    }
    let bytes = Zeroizing::new(
        base64url_to_bytes(encoded).map_err(|_| IetfSdJwtVcError::InvalidDisclosure)?,
    );
    let parsed: Value =
        serde_json::from_slice(&bytes).map_err(|_| IetfSdJwtVcError::InvalidDisclosure)?;
    let Value::Array(mut elements) = parsed else {
        let mut parsed = parsed;
        zeroize_json_value(&mut parsed);
        return Err(IetfSdJwtVcError::InvalidDisclosure);
    };
    let result = split_disclosure_elements(&mut elements);
    for element in &mut elements {
        zeroize_json_value(element);
    }
    result
}

fn split_disclosure_elements(
    elements: &mut Vec<Value>,
) -> Result<DecodedDisclosure, IetfSdJwtVcError> {
    let element_count = elements.len();
    if element_count != OBJECT_DISCLOSURE_ELEMENTS && element_count != ARRAY_DISCLOSURE_ELEMENTS {
        return Err(IetfSdJwtVcError::InvalidDisclosure);
    }
    let value = elements.pop().ok_or(IetfSdJwtVcError::InvalidDisclosure)?;
    let name = if element_count == OBJECT_DISCLOSURE_ELEMENTS {
        match elements.pop() {
            Some(Value::String(name)) => Some(name),
            _ => None,
        }
        .ok_or(IetfSdJwtVcError::InvalidDisclosure)
        .map(Some)
    } else {
        Ok(None)
    };
    let salt = match elements.pop() {
        Some(Value::String(salt)) => Some(salt),
        _ => None,
    }
    .ok_or(IetfSdJwtVcError::InvalidDisclosure);

    let content = match name? {
        Some(name) => DisclosureContent::ObjectProperty { name, value },
        None => DisclosureContent::ArrayElement { value },
    };
    let disclosure = DecodedDisclosure {
        salt: salt?,
        content,
    };
    if disclosure.salt.trim().is_empty() || disclosure.salt.len() > MAX_DISCLOSURE_SALT_BYTES {
        return Err(IetfSdJwtVcError::InvalidDisclosure);
    }
    if let DisclosureContent::ObjectProperty { name, .. } = &disclosure.content {
        if name.trim().is_empty() || SD_JWT_STRUCTURAL_CLAIMS.contains(&name.as_str()) {
            return Err(IetfSdJwtVcError::InvalidDisclosure);
        }
    }
    Ok(disclosure)
}

fn is_array_placeholder(object: &Map<String, Value>) -> bool {
    object.len() == 1 && object.contains_key(ARRAY_DIGEST_CLAIM_NAME)
}

fn collect_digests(
    value: &Value,
    position: ValuePosition,
    depth: usize,
    budget: &mut Budget,
    out: &mut BTreeSet<String>,
) -> Result<(), IetfSdJwtVcError> {
    budget.visit(depth)?;
    match value {
        Value::Object(object) => {
            if is_array_placeholder(object) {
                if position != ValuePosition::ArrayElement {
                    return Err(IetfSdJwtVcError::ReservedClaimKey);
                }
                let digest = object
                    .get(ARRAY_DIGEST_CLAIM_NAME)
                    .and_then(Value::as_str)
                    .ok_or(IetfSdJwtVcError::InvalidSdClaim)?;
                return insert_unique_digest(out, digest);
            }
            if object.contains_key(ARRAY_DIGEST_CLAIM_NAME)
                || (position != ValuePosition::Root && object.contains_key(SD_ALG_CLAIM_NAME))
            {
                return Err(IetfSdJwtVcError::ReservedClaimKey);
            }
            if let Some(sd) = object.get(SD_CLAIM_NAME) {
                let digests = sd.as_array().ok_or(IetfSdJwtVcError::InvalidSdClaim)?;
                for digest in digests {
                    let digest = digest.as_str().ok_or(IetfSdJwtVcError::InvalidSdClaim)?;
                    insert_unique_digest(out, digest)?;
                }
            }
            let child_depth = next_depth(depth)?;
            for (key, child) in object {
                if key == SD_CLAIM_NAME || key == SD_ALG_CLAIM_NAME {
                    continue;
                }
                collect_digests(child, ValuePosition::Nested, child_depth, budget, out)?;
            }
            Ok(())
        }
        Value::Array(array) => {
            let child_depth = next_depth(depth)?;
            for child in array {
                collect_digests(child, ValuePosition::ArrayElement, child_depth, budget, out)?;
            }
            Ok(())
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => Ok(()),
    }
}

fn insert_unique_digest(out: &mut BTreeSet<String>, digest: &str) -> Result<(), IetfSdJwtVcError> {
    if digest.is_empty() || !out.insert(digest.to_owned()) {
        return Err(IetfSdJwtVcError::InvalidSdClaim);
    }
    Ok(())
}

struct Resolver<'a> {
    disclosures: &'a [DecodedDisclosure],
    digest_index: &'a BTreeMap<String, usize>,
    budget: Budget,
}

impl<'a> Resolver<'a> {
    fn lookup(&self, digest: &str) -> Option<&'a DisclosureContent> {
        let disclosures: &'a [DecodedDisclosure] = self.disclosures;
        self.digest_index
            .get(digest)
            .and_then(|index| disclosures.get(*index))
            .map(|disclosure| &disclosure.content)
    }

    fn resolve(
        &mut self,
        value: &Value,
        position: ValuePosition,
        depth: usize,
    ) -> Result<Value, IetfSdJwtVcError> {
        self.budget.visit(depth)?;
        match value {
            Value::Object(object) => self.resolve_object(object, position, depth),
            Value::Array(array) => self.resolve_array(array, depth),
            Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => Ok(value.clone()),
        }
    }

    fn resolve_object(
        &mut self,
        object: &Map<String, Value>,
        position: ValuePosition,
        depth: usize,
    ) -> Result<Value, IetfSdJwtVcError> {
        let child_depth = next_depth(depth)?;
        let mut resolved = Map::new();
        for (key, child) in object {
            if key == SD_CLAIM_NAME || key == SD_ALG_CLAIM_NAME {
                continue;
            }
            let child = self.resolve(child, ValuePosition::Nested, child_depth)?;
            resolved.insert(key.clone(), child);
        }

        let digests = match object.get(SD_CLAIM_NAME) {
            Some(Value::Array(digests)) => digests.as_slice(),
            Some(_) => return Err(IetfSdJwtVcError::InvalidSdClaim),
            None => &[],
        };
        for digest in digests {
            let digest = digest.as_str().ok_or(IetfSdJwtVcError::InvalidSdClaim)?;
            match self.lookup(digest) {
                Some(DisclosureContent::ObjectProperty { name, value }) => {
                    if position == ValuePosition::Root && is_non_selectively_disclosable_claim(name)
                    {
                        return Err(IetfSdJwtVcError::ReservedClaimKey);
                    }
                    if resolved.contains_key(name) {
                        return Err(IetfSdJwtVcError::DuplicateClaimKey);
                    }
                    let name = name.clone();
                    let value = self.resolve(value, ValuePosition::Nested, child_depth)?;
                    resolved.insert(name, value);
                }
                Some(DisclosureContent::ArrayElement { .. }) => {
                    return Err(IetfSdJwtVcError::InvalidDisclosure);
                }
                None => {}
            }
        }
        Ok(Value::Object(resolved))
    }

    fn resolve_array(&mut self, array: &[Value], depth: usize) -> Result<Value, IetfSdJwtVcError> {
        let child_depth = next_depth(depth)?;
        let mut resolved = Vec::with_capacity(array.len());
        for item in array {
            if let Value::Object(object) = item {
                if is_array_placeholder(object) {
                    let digest = object
                        .get(ARRAY_DIGEST_CLAIM_NAME)
                        .and_then(Value::as_str)
                        .ok_or(IetfSdJwtVcError::InvalidSdClaim)?;
                    match self.lookup(digest) {
                        Some(DisclosureContent::ArrayElement { value }) => {
                            let value = self.resolve(value, ValuePosition::Nested, child_depth)?;
                            resolved.push(value);
                        }
                        Some(DisclosureContent::ObjectProperty { .. }) => {
                            return Err(IetfSdJwtVcError::InvalidDisclosure);
                        }
                        None => {}
                    }
                    continue;
                }
            }
            resolved.push(self.resolve(item, ValuePosition::ArrayElement, child_depth)?);
        }
        Ok(Value::Array(resolved))
    }
}
