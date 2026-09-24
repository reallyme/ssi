// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::collections::BTreeSet;

use identity_credential_claims_core::MAX_CLAIM_PATH_BYTES;
use reallyme_credential::committed::issue::{
    MAX_COMMITMENT_CLAIMS, MAX_COMMITMENT_SALT_BYTES, MAX_COMMITMENT_VALUE_BYTES,
    MIN_COMMITMENT_SALT_BYTES,
};

// This cap is deliberately larger than the largest permitted decoded value,
// while still preventing a single base64url disclosure from causing an
// attacker-controlled multi-gigabyte allocation before structural checks run.
const MAX_ENCODED_DISCLOSURE_BYTES: usize = 2_000_000;

fn verify_merkle_disclosures(
    presentation: &SdJwtVcPresentation,
    credential: &CredentialEnvelope,
) -> Result<Vec<VerifiedDisclosure>, SdJwtVpError> {
    let commitment = &credential.claims_commitment;
    let max_value_len = usize::try_from(commitment.limits.max_value_len)
        .map_err(|_| SdJwtVpError::InvalidBundle)?;
    let expected_salt_len = usize::try_from(commitment.limits.salt_len)
        .map_err(|_| SdJwtVpError::InvalidBundle)?;
    let max_tree_leaves = MAX_COMMITMENT_CLAIMS
        .checked_next_power_of_two()
        .ok_or(SdJwtVpError::InvalidBundle)?;
    let max_merkle_depth = usize::try_from(max_tree_leaves.trailing_zeros())
        .map_err(|_| SdJwtVpError::InvalidBundle)?;

    if commitment.merkle_root.len() != 32
        || commitment.limits.salt_len < MIN_COMMITMENT_SALT_BYTES
        || commitment.limits.salt_len > MAX_COMMITMENT_SALT_BYTES
        || commitment.limits.max_value_len == 0
        || commitment.limits.max_value_len > MAX_COMMITMENT_VALUE_BYTES
        || presentation.disclosures.len() > MAX_COMMITMENT_CLAIMS
    {
        return Err(SdJwtVpError::InvalidBundle);
    }

    let mut output = Vec::new();
    output
        .try_reserve(presentation.disclosures.len())
        .map_err(|_| SdJwtVpError::InvalidBundle)?;
    let mut observed_indices = BTreeSet::new();
    let mut observed_merkle_depth = None;

    for encoded_disclosure in &presentation.disclosures {
        if encoded_disclosure.len() > MAX_ENCODED_DISCLOSURE_BYTES {
            return Err(SdJwtVpError::InvalidDisclosure);
        }
        let disclosure_bytes = base64url_to_bytes(encoded_disclosure)
            .map_err(|_| SdJwtVpError::InvalidDisclosure)?;
        let disclosure: serde_json::Value = serde_json::from_slice(&disclosure_bytes)
            .map_err(|_| SdJwtVpError::InvalidDisclosure)?;
        let fields = disclosure
            .as_array()
            .ok_or(SdJwtVpError::InvalidDisclosure)?;

        // Legacy disclosures are [salt, claim path, value, index, Merkle path].
        if fields.len() != 5 {
            return Err(SdJwtVpError::InvalidDisclosure);
        }

        let salt_b64u = fields[0]
            .as_str()
            .ok_or(SdJwtVpError::InvalidDisclosure)?;
        let claim_path = fields[1]
            .as_str()
            .ok_or(SdJwtVpError::InvalidDisclosure)?;
        if claim_path.len() > MAX_CLAIM_PATH_BYTES {
            return Err(SdJwtVpError::InvalidDisclosure);
        }
        let claim_path = claim_path.to_owned();
        let value_b64u = fields[2]
            .as_str()
            .ok_or(SdJwtVpError::InvalidDisclosure)?;
        let index = usize::try_from(
            fields[3]
                .as_u64()
                .ok_or(SdJwtVpError::InvalidDisclosure)?,
        )
        .map_err(|_| SdJwtVpError::InvalidDisclosure)?;
        let path = fields[4]
            .as_array()
            .ok_or(SdJwtVpError::InvalidDisclosure)?;

        if path.len() > max_merkle_depth
            || observed_merkle_depth.is_some_and(|depth| depth != path.len())
        {
            return Err(SdJwtVpError::InvalidDisclosure);
        }
        observed_merkle_depth = Some(path.len());

        let path_depth = u32::try_from(path.len())
            .map_err(|_| SdJwtVpError::InvalidDisclosure)?;
        let index_bound = 1_usize
            .checked_shl(path_depth)
            .ok_or(SdJwtVpError::InvalidDisclosure)?;
        if index >= index_bound || !observed_indices.insert(index) {
            return Err(SdJwtVpError::InvalidDisclosure);
        }

        let salt = base64url_to_bytes(salt_b64u)
            .map_err(|_| SdJwtVpError::InvalidDisclosure)?;
        let value = base64url_to_bytes(value_b64u)
            .map_err(|_| SdJwtVpError::InvalidDisclosure)?;
        if salt.len() != expected_salt_len || value.len() > max_value_len {
            return Err(SdJwtVpError::InvalidDisclosure);
        }

        let mut merkle_path = Vec::new();
        merkle_path
            .try_reserve(path.len())
            .map_err(|_| SdJwtVpError::InvalidDisclosure)?;
        for sibling in path {
            let encoded_sibling = sibling
                .as_str()
                .ok_or(SdJwtVpError::InvalidDisclosure)?;
            let sibling_bytes = base64url_to_bytes(encoded_sibling)
                .map_err(|_| SdJwtVpError::InvalidDisclosure)?;
            let sibling_hash: [u8; 32] = sibling_bytes
                .as_slice()
                .try_into()
                .map_err(|_| SdJwtVpError::InvalidDisclosure)?;
            merkle_path.push(sibling_hash);
        }

        let inner = claim_inner_digest(commitment.domain_tags.clm.as_bytes(), &value, &salt)?;
        let leaf = leaf_digest(
            commitment.domain_tags.leaf.as_bytes(),
            &claim_path,
            &inner,
        )?;
        let mut computed_root = leaf;
        let mut current_index = index;
        for sibling in &merkle_path {
            computed_root = if (current_index & 1) == 0 {
                node_digest(
                    commitment.domain_tags.node.as_bytes(),
                    &computed_root,
                    sibling,
                )?
            } else {
                node_digest(
                    commitment.domain_tags.node.as_bytes(),
                    sibling,
                    &computed_root,
                )?
            };
            current_index >>= 1;
        }

        if computed_root.as_slice() != commitment.merkle_root.as_slice() {
            return Err(SdJwtVpError::InvalidDisclosure);
        }
        output.push(VerifiedDisclosure {
            claim_path,
            value_jcs: value,
        });
    }

    Ok(output)
}
