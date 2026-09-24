// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Selective-disclosure projection over an already authenticated SD-JWT payload.

use core::fmt;

use serde_json::Value;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::sensitive::zeroize_json_value;
use crate::{
    decode_disclosure, digest_disclosure, Disclosure, DisclosureKind, SdJwtEnvelopeError,
    SdJwtHashAlgorithm, SdJwtProcessingPolicy, MAX_SD_JWT_DISCLOSURES,
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
    original_index: usize,
    digest: String,
    disclosure: Disclosure,
    path: Option<Vec<SdJwtClaimPathComponent>>,
}

impl Drop for MappedDisclosure {
    fn drop(&mut self) {
        self.digest.zeroize();
        self.path.zeroize();
    }
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
    let hash_algorithm = resolve_hash_algorithm(issuer_payload)?;
    let mut mapped = Vec::with_capacity(encoded_disclosures.len());
    for (original_index, encoded) in encoded_disclosures.iter().enumerate() {
        let disclosure = decode_disclosure(encoded)?;
        let digest = digest_disclosure(encoded, hash_algorithm)?;
        if mapped
            .iter()
            .any(|existing: &MappedDisclosure| existing.digest == digest)
        {
            return Err(SdJwtEnvelopeError::DuplicateDisclosure);
        }
        mapped.push(MappedDisclosure {
            original_index,
            digest,
            disclosure,
            path: None,
        });
    }

    let mut nodes = 0_usize;
    map_disclosure_paths(issuer_payload, &[], 0, policy, &mut nodes, &mut mapped)?;
    if mapped.iter().any(|entry| entry.path.is_none()) {
        return Err(SdJwtEnvelopeError::UnmatchedDisclosure);
    }

    mapped.sort_unstable_by_key(|entry| entry.original_index);
    let mut selected = Vec::new();
    for entry in mapped {
        let path = entry
            .path
            .as_deref()
            .ok_or(SdJwtEnvelopeError::UnmatchedDisclosure)?;
        if requested_paths
            .iter()
            .any(|requested| disclosure_is_required(path, requested))
        {
            selected.push(entry.disclosure.encoded().to_owned());
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

fn map_disclosure_paths(
    value: &Value,
    path: &[SdJwtClaimPathComponent],
    depth: usize,
    policy: SdJwtProcessingPolicy,
    nodes: &mut usize,
    mapped: &mut [MappedDisclosure],
) -> Result<(), SdJwtEnvelopeError> {
    if depth > policy.max_depth {
        return Err(SdJwtEnvelopeError::ProcessingDepthExceeded);
    }
    *nodes = nodes
        .checked_add(1)
        .ok_or(SdJwtEnvelopeError::ProcessingNodeLimitExceeded)?;
    if *nodes > policy.max_nodes {
        return Err(SdJwtEnvelopeError::ProcessingNodeLimitExceeded);
    }
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
                    map_object_disclosure(digest, path, depth, policy, nodes, mapped)?;
                }
            }
            for (name, child) in object {
                if name == SD_CLAIM_NAME || name == SD_ALG_CLAIM_NAME {
                    continue;
                }
                let mut child_path = path.to_vec();
                child_path.push(SdJwtClaimPathComponent::Name(name.clone()));
                map_disclosure_paths(child, &child_path, depth + 1, policy, nodes, mapped)?;
            }
        }
        Value::Array(array) => {
            for (index, child) in array.iter().enumerate() {
                let mut child_path = path.to_vec();
                child_path.push(SdJwtClaimPathComponent::Index(index));
                if let Some(digest) = array_disclosure_digest(child)? {
                    map_array_disclosure(digest, &child_path, depth, policy, nodes, mapped)?;
                } else {
                    map_disclosure_paths(child, &child_path, depth + 1, policy, nodes, mapped)?;
                }
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
    Ok(())
}

fn map_object_disclosure(
    digest: &str,
    parent_path: &[SdJwtClaimPathComponent],
    depth: usize,
    policy: SdJwtProcessingPolicy,
    nodes: &mut usize,
    mapped: &mut [MappedDisclosure],
) -> Result<(), SdJwtEnvelopeError> {
    let Some(index) = mapped.iter().position(|entry| entry.digest == digest) else {
        return Ok(());
    };
    let (claim_name, mut claim_value) = match mapped[index].disclosure.kind() {
        DisclosureKind::ObjectProperty {
            claim_name,
            claim_value,
        } => (claim_name.clone(), claim_value.clone()),
        DisclosureKind::ArrayElement { .. } => {
            return Err(SdJwtEnvelopeError::InvalidDigestPlaceholder);
        }
    };
    let mut child_path = parent_path.to_vec();
    child_path.push(SdJwtClaimPathComponent::Name(claim_name));
    set_mapped_path(&mut mapped[index], child_path.clone())?;
    let result = map_disclosure_paths(&claim_value, &child_path, depth + 1, policy, nodes, mapped);
    zeroize_json_value(&mut claim_value);
    result
}

fn map_array_disclosure(
    digest: &str,
    child_path: &[SdJwtClaimPathComponent],
    depth: usize,
    policy: SdJwtProcessingPolicy,
    nodes: &mut usize,
    mapped: &mut [MappedDisclosure],
) -> Result<(), SdJwtEnvelopeError> {
    let Some(index) = mapped.iter().position(|entry| entry.digest == digest) else {
        return Ok(());
    };
    let mut claim_value = match mapped[index].disclosure.kind() {
        DisclosureKind::ArrayElement { claim_value } => claim_value.clone(),
        DisclosureKind::ObjectProperty { .. } => {
            return Err(SdJwtEnvelopeError::InvalidDigestPlaceholder);
        }
    };
    set_mapped_path(&mut mapped[index], child_path.to_vec())?;
    let result = map_disclosure_paths(&claim_value, child_path, depth + 1, policy, nodes, mapped);
    zeroize_json_value(&mut claim_value);
    result
}

fn set_mapped_path(
    entry: &mut MappedDisclosure,
    path: Vec<SdJwtClaimPathComponent>,
) -> Result<(), SdJwtEnvelopeError> {
    if entry.path.is_some() {
        return Err(SdJwtEnvelopeError::DuplicateDigest);
    }
    entry.path = Some(path);
    Ok(())
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
