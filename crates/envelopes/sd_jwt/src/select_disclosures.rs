// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Selective-disclosure projection over an already authenticated SD-JWT payload.

use core::fmt;
use std::collections::HashMap;

use serde_json::Value;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::sensitive::zeroize_json_value;
use crate::{
    decode_disclosure, digest_disclosure, DisclosureKind, SdJwtEnvelopeError, SdJwtHashAlgorithm,
    SdJwtProcessingPolicy, MAX_SD_JWT_DISCLOSURES,
};

const SD_CLAIM_NAME: &str = "_sd";
const SD_ALG_CLAIM_NAME: &str = "_sd_alg";
const ARRAY_DIGEST_CLAIM_NAME: &str = "...";

/// One component in a claim path requested for disclosure.
#[derive(Clone, PartialEq, Eq, Zeroize)]
#[zeroize(drop)]
pub enum SdJwtClaimPathComponent {
    /// Select an object property.
    Name(String),
    /// Select a concrete array position.
    Index(usize),
    /// Select every element at this array position.
    All,
}

impl fmt::Debug for SdJwtClaimPathComponent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Name(_) => formatter.write_str("Name([REDACTED])"),
            Self::Index(index) => formatter.debug_tuple("Index").field(index).finish(),
            Self::All => formatter.write_str("All"),
        }
    }
}

/// Exact encoded disclosures selected in original compact-serialization order.
pub struct SelectedSdJwtDisclosures {
    disclosures: Vec<String>,
}

impl SelectedSdJwtDisclosures {
    /// Borrow selected encoded disclosures.
    #[must_use]
    pub fn as_slice(&self) -> &[String] {
        &self.disclosures
    }

    /// Return the number of selected disclosures.
    #[must_use]
    pub fn len(&self) -> usize {
        self.disclosures.len()
    }

    /// Whether no disclosure was needed for the requested clear-text claims.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.disclosures.is_empty()
    }
}

impl fmt::Debug for SelectedSdJwtDisclosures {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SelectedSdJwtDisclosures")
            .field("count", &self.disclosures.len())
            .field("values", &"<redacted>")
            .finish()
    }
}

impl Zeroize for SelectedSdJwtDisclosures {
    fn zeroize(&mut self) {
        self.disclosures.zeroize();
    }
}

impl Drop for SelectedSdJwtDisclosures {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for SelectedSdJwtDisclosures {}

struct MappedDisclosure {
    encoded: String,
    kind: DisclosureKind,
    path: Option<Vec<SdJwtClaimPathComponent>>,
}

impl Drop for MappedDisclosure {
    fn drop(&mut self) {
        self.encoded.zeroize();
        self.path.zeroize();
    }
}

/// Decoded disclosures indexed by digest, in original serialization order.
struct DisclosureGraph {
    entries: Vec<MappedDisclosure>,
    index_by_digest: HashMap<String, usize>,
}

impl Drop for DisclosureGraph {
    fn drop(&mut self) {
        for (mut digest, _) in self.index_by_digest.drain() {
            digest.zeroize();
        }
    }
}

/// Mutable traversal state shared across the recursive path mapping.
struct PathMapper<'a> {
    graph: &'a mut DisclosureGraph,
    policy: SdJwtProcessingPolicy,
    nodes: usize,
    path: Vec<SdJwtClaimPathComponent>,
}

/// Select the minimal disclosure closure needed for the requested claim paths.
///
/// Parent disclosures are retained automatically when a requested nested claim
/// is reachable only through that parent. Decoys remain undisclosed. The input
/// payload must be the authenticated issuer JWT payload; this function owns
/// structural, digest, depth, node-count, and duplicate validation for the
/// disclosure graph itself.
pub fn select_sd_jwt_disclosures(
    issuer_payload: &Value,
    encoded_disclosures: &[String],
    requested_paths: &[Vec<SdJwtClaimPathComponent>],
    policy: SdJwtProcessingPolicy,
) -> Result<SelectedSdJwtDisclosures, SdJwtEnvelopeError> {
    if !issuer_payload.is_object()
        || encoded_disclosures.len() > MAX_SD_JWT_DISCLOSURES
        || policy.max_depth == 0
        || policy.max_nodes == 0
        || requested_paths.iter().any(Vec::is_empty)
    {
        return Err(SdJwtEnvelopeError::InvalidIssuanceInput);
    }
    let policy = policy.clamped();
    let hash_algorithm = resolve_hash_algorithm(issuer_payload)?;
    let mut graph = DisclosureGraph {
        entries: Vec::with_capacity(encoded_disclosures.len()),
        index_by_digest: HashMap::with_capacity(encoded_disclosures.len()),
    };
    for (original_index, encoded) in encoded_disclosures.iter().enumerate() {
        let disclosure = decode_disclosure(encoded)?;
        let digest = digest_disclosure(encoded, hash_algorithm)?;
        if graph
            .index_by_digest
            .insert(digest, original_index)
            .is_some()
        {
            return Err(SdJwtEnvelopeError::DuplicateDisclosure);
        }
        graph.entries.push(MappedDisclosure {
            encoded: disclosure.encoded().to_owned(),
            kind: disclosure.into_kind(),
            path: None,
        });
    }

    let mut mapper = PathMapper {
        graph: &mut graph,
        policy,
        nodes: 0,
        path: Vec::new(),
    };
    mapper.map_value(issuer_payload, 0)?;
    if graph.entries.iter().any(|entry| entry.path.is_none()) {
        return Err(SdJwtEnvelopeError::UnmatchedDisclosure);
    }

    let mut selected = Vec::new();
    for entry in &graph.entries {
        let path = entry
            .path
            .as_deref()
            .ok_or(SdJwtEnvelopeError::UnmatchedDisclosure)?;
        if requested_paths
            .iter()
            .any(|requested| disclosure_is_required(path, requested))
        {
            selected.push(entry.encoded.clone());
        }
    }
    Ok(SelectedSdJwtDisclosures {
        disclosures: selected,
    })
}

fn resolve_hash_algorithm(payload: &Value) -> Result<SdJwtHashAlgorithm, SdJwtEnvelopeError> {
    match payload.get(SD_ALG_CLAIM_NAME) {
        Some(Value::String(value)) => SdJwtHashAlgorithm::parse(value),
        Some(_) => Err(SdJwtEnvelopeError::InvalidHashAlgorithmClaim),
        None => Ok(SdJwtHashAlgorithm::default_for_sd_jwt()),
    }
}

impl PathMapper<'_> {
    fn count_node(&mut self, depth: usize) -> Result<(), SdJwtEnvelopeError> {
        if depth > self.policy.max_depth {
            return Err(SdJwtEnvelopeError::ProcessingDepthExceeded);
        }
        self.nodes = self
            .nodes
            .checked_add(1)
            .ok_or(SdJwtEnvelopeError::ProcessingNodeLimitExceeded)?;
        if self.nodes > self.policy.max_nodes {
            return Err(SdJwtEnvelopeError::ProcessingNodeLimitExceeded);
        }
        Ok(())
    }

    fn map_value(&mut self, value: &Value, depth: usize) -> Result<(), SdJwtEnvelopeError> {
        self.count_node(depth)?;
        let child_depth = depth
            .checked_add(1)
            .ok_or(SdJwtEnvelopeError::ProcessingDepthExceeded)?;
        match value {
            Value::Object(object) => {
                if let Some(digests) = object.get(SD_CLAIM_NAME) {
                    let digests = digests
                        .as_array()
                        .ok_or(SdJwtEnvelopeError::InvalidDigestPlaceholder)?;
                    for digest in digests {
                        let digest = digest
                            .as_str()
                            .ok_or(SdJwtEnvelopeError::InvalidDigestPlaceholder)?;
                        self.map_object_disclosure(digest, child_depth)?;
                    }
                }
                for (name, child) in object {
                    if name == SD_CLAIM_NAME || name == SD_ALG_CLAIM_NAME {
                        continue;
                    }
                    self.path.push(SdJwtClaimPathComponent::Name(name.clone()));
                    let result = self.map_value(child, child_depth);
                    self.path.pop();
                    result?;
                }
            }
            Value::Array(array) => {
                for (index, child) in array.iter().enumerate() {
                    self.path.push(SdJwtClaimPathComponent::Index(index));
                    let result = match array_disclosure_digest(child)? {
                        Some(digest) => self.map_array_disclosure(digest, child_depth),
                        None => self.map_value(child, child_depth),
                    };
                    self.path.pop();
                    result?;
                }
            }
            Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
        }
        Ok(())
    }

    fn map_object_disclosure(
        &mut self,
        digest: &str,
        depth: usize,
    ) -> Result<(), SdJwtEnvelopeError> {
        let Some(&index) = self.graph.index_by_digest.get(digest) else {
            return Ok(());
        };
        let claim_name = match &self.entry(index)?.kind {
            DisclosureKind::ObjectProperty { claim_name, .. } => claim_name.clone(),
            DisclosureKind::ArrayElement { .. } => {
                return Err(SdJwtEnvelopeError::InvalidDigestPlaceholder);
            }
        };
        self.path.push(SdJwtClaimPathComponent::Name(claim_name));
        let result = self.map_disclosed_value(index, depth);
        self.path.pop();
        result
    }

    fn map_array_disclosure(
        &mut self,
        digest: &str,
        depth: usize,
    ) -> Result<(), SdJwtEnvelopeError> {
        let Some(&index) = self.graph.index_by_digest.get(digest) else {
            return Ok(());
        };
        if matches!(
            self.entry(index)?.kind,
            DisclosureKind::ObjectProperty { .. }
        ) {
            return Err(SdJwtEnvelopeError::InvalidDigestPlaceholder);
        }
        self.map_disclosed_value(index, depth)
    }

    /// Record the current path for one disclosure, then walk its value.
    ///
    /// Each disclosure is visited at most once (a second visit is a duplicate
    /// digest), and selection only needs the encoded form afterwards, so the
    /// plaintext value is moved out and wiped instead of being cloned.
    fn map_disclosed_value(
        &mut self,
        index: usize,
        depth: usize,
    ) -> Result<(), SdJwtEnvelopeError> {
        let path = self.path.clone();
        let entry = self.entry_mut(index)?;
        if entry.path.is_some() {
            return Err(SdJwtEnvelopeError::DuplicateDigest);
        }
        entry.path = Some(path);
        let mut claim_value = match &mut entry.kind {
            DisclosureKind::ObjectProperty { claim_value, .. }
            | DisclosureKind::ArrayElement { claim_value } => core::mem::take(claim_value),
        };
        let result = self.map_value(&claim_value, depth);
        zeroize_json_value(&mut claim_value);
        result
    }

    fn entry(&self, index: usize) -> Result<&MappedDisclosure, SdJwtEnvelopeError> {
        self.graph
            .entries
            .get(index)
            .ok_or(SdJwtEnvelopeError::UnmatchedDisclosure)
    }

    fn entry_mut(&mut self, index: usize) -> Result<&mut MappedDisclosure, SdJwtEnvelopeError> {
        self.graph
            .entries
            .get_mut(index)
            .ok_or(SdJwtEnvelopeError::UnmatchedDisclosure)
    }
}

fn array_disclosure_digest(value: &Value) -> Result<Option<&str>, SdJwtEnvelopeError> {
    let Value::Object(object) = value else {
        return Ok(None);
    };
    let Some(digest) = object.get(ARRAY_DIGEST_CLAIM_NAME) else {
        return Ok(None);
    };
    if object.len() != 1 {
        return Err(SdJwtEnvelopeError::InvalidDigestPlaceholder);
    }
    digest
        .as_str()
        .map(Some)
        .ok_or(SdJwtEnvelopeError::InvalidDigestPlaceholder)
}

fn disclosure_is_required(
    disclosure_path: &[SdJwtClaimPathComponent],
    requested_path: &[SdJwtClaimPathComponent],
) -> bool {
    disclosure_path.len() <= requested_path.len()
        && disclosure_path
            .iter()
            .zip(requested_path)
            .all(|(disclosure, requested)| match (disclosure, requested) {
                (SdJwtClaimPathComponent::Index(_), SdJwtClaimPathComponent::All) => true,
                (left, right) => left == right,
            })
}

#[cfg(test)]
#[path = "select_disclosures_tests.rs"]
mod tests;
