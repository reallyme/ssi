// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

fn write_canonical_claim_value(value: &ClaimValue, out: &mut Vec<u8>) -> Result<(), ClaimsError> {
    match value {
        ClaimValue::Null => out.extend_from_slice(br#"{"t":"null","v":null}"#),
        ClaimValue::Boolean(value) => {
            out.extend_from_slice(br#"{"t":"boolean","v":"#);
            if *value {
                out.extend_from_slice(b"true");
            } else {
                out.extend_from_slice(b"false");
            }
            out.push(b'}');
        }
        ClaimValue::String(value) => {
            write_tagged_string(out, "string", value.as_str())?;
        }
        ClaimValue::Signed(value) => {
            out.extend_from_slice(br#"{"t":"signed","v":"#);
            out.extend_from_slice(value.to_string().as_bytes());
            out.push(b'}');
        }
        ClaimValue::Unsigned(value) => {
            out.extend_from_slice(br#"{"t":"unsigned","v":"#);
            out.extend_from_slice(value.to_string().as_bytes());
            out.push(b'}');
        }
        ClaimValue::Decimal(value) => {
            write_tagged_string(out, "decimal", value.as_str())?;
        }
        ClaimValue::Bytes(value) => {
            let encoded = bytes_to_base64url(value);
            write_tagged_string(out, "bytes", encoded.as_str())?;
        }
        ClaimValue::Date(value) => {
            write_tagged_string(out, "date", value.as_str())?;
        }
        ClaimValue::DateTime(value) => {
            write_tagged_string(out, "date-time", value.as_str())?;
        }
        ClaimValue::Array(values) => {
            out.extend_from_slice(br#"{"t":"array","v":["#);
            for (index, item) in values.iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                write_canonical_claim_value(item, out)?;
            }
            out.extend_from_slice(b"]}");
        }
        ClaimValue::Object(values) => {
            out.extend_from_slice(br#"{"t":"object","v":{"#);
            for (index, (key, item)) in values.iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                write_json_string(out, key.as_str())?;
                out.push(b':');
                write_canonical_claim_value(item, out)?;
            }
            out.extend_from_slice(b"}}");
        }
    }
    Ok(())
}

fn write_tagged_string(out: &mut Vec<u8>, tag: &str, value: &str) -> Result<(), ClaimsError> {
    out.extend_from_slice(br#"{"t":"#);
    write_json_string(out, tag)?;
    out.extend_from_slice(br#","v":"#);
    write_json_string(out, value)?;
    out.push(b'}');
    Ok(())
}

fn write_json_string(out: &mut Vec<u8>, value: &str) -> Result<(), ClaimsError> {
    serde_json::to_writer(&mut *out, value)
        .map_err(|_| ClaimsError::InvalidInput(ClaimsInvalidReason::InvalidClaimPayloadJson))
}

struct BuiltMerkleTree {
    root: Vec<u8>,
    depth: u32,
    levels: Vec<Vec<Vec<u8>>>,
}

fn build_merkle_tree(
    tags: &DomainTags,
    mut leaves: Vec<Vec<u8>>,
) -> Result<BuiltMerkleTree, ClaimsError> {
    if leaves.is_empty() || leaves.len() > MAX_CLAIM_OPENINGS_PER_BUNDLE {
        return Err(ClaimsError::InvalidInput(
            ClaimsInvalidReason::InvalidPrivateBundleTree,
        ));
    }

    let mut levels = Vec::new();
    levels.push(leaves.clone());
    let mut depth = 0_u32;
    while leaves.len() > 1 {
        let mut next = Vec::with_capacity(checked_padded_parent_len(leaves.len())?);
        let mut index = 0_usize;
        while index < leaves.len() {
            let right_index = index.checked_add(1).ok_or(ClaimsError::InvalidInput(
                ClaimsInvalidReason::InvalidPrivateBundleTree,
            ))?;
            let right = if right_index < leaves.len() {
                leaves[right_index].as_slice()
            } else {
                leaves[index].as_slice()
            };
            next.push(merkle_node_hash(tags, leaves[index].as_slice(), right)?);
            index = index.checked_add(2).ok_or(ClaimsError::InvalidInput(
                ClaimsInvalidReason::InvalidPrivateBundleTree,
            ))?;
        }
        depth = depth.checked_add(1).ok_or(ClaimsError::InvalidInput(
            ClaimsInvalidReason::InvalidPrivateBundleTree,
        ))?;
        leaves = next;
        levels.push(leaves.clone());
    }

    let depth_len = usize::try_from(depth)
        .map_err(|_| ClaimsError::InvalidInput(ClaimsInvalidReason::InvalidPrivateBundleTree))?;
    if depth_len > MAX_CLAIM_OPENING_MERKLE_DEPTH {
        return Err(ClaimsError::InvalidInput(
            ClaimsInvalidReason::InvalidPrivateBundleTree,
        ));
    }
    let Some(root_level) = levels.last() else {
        return Err(ClaimsError::InvalidInput(
            ClaimsInvalidReason::InvalidPrivateBundleTree,
        ));
    };
    let Some(root) = root_level.first() else {
        return Err(ClaimsError::InvalidInput(
            ClaimsInvalidReason::InvalidPrivateBundleTree,
        ));
    };

    Ok(BuiltMerkleTree {
        root: root.clone(),
        depth,
        levels,
    })
}

fn merkle_proof_for_index(
    levels: &[Vec<Vec<u8>>],
    mut index: usize,
) -> Result<Vec<Vec<u8>>, ClaimsError> {
    if levels.is_empty() {
        return Err(ClaimsError::InvalidInput(
            ClaimsInvalidReason::InvalidPrivateBundleTree,
        ));
    }
    let proof_len = levels
        .len()
        .checked_sub(1)
        .ok_or(ClaimsError::InvalidInput(
            ClaimsInvalidReason::InvalidPrivateBundleTree,
        ))?;
    let mut proof = Vec::with_capacity(proof_len);
    for level in &levels[..proof_len] {
        if index >= level.len() {
            return Err(ClaimsError::InvalidInput(
                ClaimsInvalidReason::InvalidPrivateBundleTree,
            ));
        }
        let sibling_index = if index.is_multiple_of(2) {
            index.checked_add(1).ok_or(ClaimsError::InvalidInput(
                ClaimsInvalidReason::InvalidPrivateBundleTree,
            ))?
        } else {
            index.checked_sub(1).ok_or(ClaimsError::InvalidInput(
                ClaimsInvalidReason::InvalidPrivateBundleTree,
            ))?
        };
        if sibling_index < level.len() {
            proof.push(level[sibling_index].clone());
        } else {
            proof.push(level[index].clone());
        }
        index /= 2;
    }
    Ok(proof)
}

fn checked_padded_parent_len(len: usize) -> Result<usize, ClaimsError> {
    let padded = len.checked_add(1).ok_or(ClaimsError::InvalidInput(
        ClaimsInvalidReason::InvalidPrivateBundleTree,
    ))?;
    Ok(padded / 2)
}

fn merkle_depth_for_leaf_count(mut count: usize) -> Result<u32, ClaimsError> {
    if count == 0 {
        return Err(ClaimsError::InvalidInput(
            ClaimsInvalidReason::InvalidPrivateBundleTree,
        ));
    }
    let mut depth = 0_u32;
    while count > 1 {
        count = checked_padded_parent_len(count)?;
        depth = depth.checked_add(1).ok_or(ClaimsError::InvalidInput(
            ClaimsInvalidReason::InvalidPrivateBundleTree,
        ))?;
    }
    Ok(depth)
}

fn claim_leaf_hash(
    tags: &DomainTags,
    claim_path: &str,
    value: &[u8],
    salt: &[u8],
) -> Result<Vec<u8>, ClaimsError> {
    let inner = claim_value_hash(tags, value, salt)?;
    let path_hash = sha2_256_digest(claim_path.as_bytes());
    digest_parts(&[tags.leaf.as_bytes(), path_hash.as_bytes(), inner.as_slice()])
}

fn claim_value_hash(tags: &DomainTags, value: &[u8], salt: &[u8]) -> Result<Vec<u8>, ClaimsError> {
    let value_len = u64::try_from(value.len())
        .map_err(|_| ClaimsError::InvalidInput(ClaimsInvalidReason::ClaimValueLimitExceeded))?;
    let encoded_len = value_len.to_be_bytes();
    digest_parts(&[tags.clm.as_bytes(), encoded_len.as_slice(), value, salt])
}

fn merkle_node_hash(tags: &DomainTags, left: &[u8], right: &[u8]) -> Result<Vec<u8>, ClaimsError> {
    digest_parts(&[tags.node.as_bytes(), left, right])
}

fn digest_parts(parts: &[&[u8]]) -> Result<Vec<u8>, ClaimsError> {
    let capacity = parts.iter().try_fold(0_usize, |total, part| {
        total
            .checked_add(part.len())
            .ok_or(ClaimsError::InvalidInput(
                ClaimsInvalidReason::ClaimValueLimitExceeded,
            ))
    })?;
    let mut input = Vec::with_capacity(capacity);
    for part in parts {
        input.extend_from_slice(part);
    }
    Ok(sha2_256_digest(&input).as_bytes().to_vec())
}

fn validate_domain_tags(tags: &DomainTags) -> Result<(), ClaimsError> {
    validate_required_label(tags.clm.as_str(), MAX_COMMITMENT_DOMAIN_TAG_BYTES)?;
    validate_required_label(tags.leaf.as_str(), MAX_COMMITMENT_DOMAIN_TAG_BYTES)?;
    validate_required_label(tags.node.as_str(), MAX_COMMITMENT_DOMAIN_TAG_BYTES)
        .map_err(|_| ClaimsError::InvalidInput(ClaimsInvalidReason::InvalidCommitmentDomainTags))
}

fn validate_commitment_limits(limits: CommitmentLimits) -> Result<(), ClaimsError> {
    if limits.max_value_len == 0 || limits.salt_len == 0 {
        return Err(ClaimsError::InvalidInput(
            ClaimsInvalidReason::InvalidCommitmentMaterial,
        ));
    }
    let max_value_len = usize::try_from(limits.max_value_len)
        .map_err(|_| ClaimsError::InvalidInput(ClaimsInvalidReason::InvalidCommitmentMaterial))?;
    if max_value_len > MAX_CLAIM_BYTES_VALUE_BYTES {
        return Err(ClaimsError::InvalidInput(
            ClaimsInvalidReason::ClaimValueLimitExceeded,
        ));
    }
    Ok(())
}

fn validate_required_label(value: &str, limit: usize) -> Result<(), ClaimsError> {
    if value.trim().is_empty() || value.len() > limit {
        Err(ClaimsError::InvalidInput(
            ClaimsInvalidReason::InvalidCommitmentMaterial,
        ))
    } else {
        Ok(())
    }
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

#[cfg(test)]
#[allow(clippy::expect_used)]
#[path = "section_04_public_key_representation_tests.rs"]
mod public_key_representation_tests;
