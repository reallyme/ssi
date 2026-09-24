// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::collections::BTreeSet;

use reallyme_crypto::{p256::p256_ecdsa_jose_signature_to_der, sha2::digest as sha2_256_digest};
use zeroize::Zeroizing;

use crypto_core::Algorithm as CryptoAlg;
use crypto_dispatch::verify as dispatch_verify;

use crate::committed::{
    canonical::canonical_credential_bytes,
    error::VcError,
    issue::{
        MAX_COMMITMENT_CLAIMS, MAX_COMMITMENT_SALT_BYTES, MAX_COMMITMENT_VALUE_BYTES,
        MIN_COMMITMENT_SALT_BYTES,
    },
    model::{ClaimsCommitment, CredentialEnvelope, SubjectPrivateBundle},
};

/// Result of VC verification.
#[derive(Debug, Clone)]
pub struct VerifyResult {
    pub envelope_hash: [u8; 32],
}

/// Verify a credential envelope and optional subject bundle.
///
/// This performs **cryptographic and structural verification only**:
/// - canonical CBOR bytes are recomputed
/// - issuer signature is verified
/// - envelope hash is checked
/// - Merkle openings are verified (if provided)
///
/// This does NOT:
/// - resolve issuer DID
/// - check revocation lists
/// - enforce semantic claim policies
/// - validate assurance/profile rules
pub fn verify_credential(
    envelope: &CredentialEnvelope,
    issuer_crypto_alg: CryptoAlg,
    issuer_public_key: &[u8],
    subject_bundle: Option<&SubjectPrivateBundle>,
) -> Result<VerifyResult, VcError> {
    // 1) Canonical CBOR bytes
    let canonical = canonical_credential_bytes(envelope).map_err(|_| VcError::Canonicalization)?;

    let envelope_hash = sha256(&canonical);

    // 2) Verify issuer signature
    let sig = &envelope.issuer_signature;

    if sig.verification_key.alg != issuer_credential_algorithm(issuer_crypto_alg)? {
        return Err(VcError::InvalidCredential);
    }

    let normalized_signature = match issuer_crypto_alg {
        CryptoAlg::P256 => {
            p256_ecdsa_jose_signature_to_der(&sig.raw_rs).map_err(|_| VcError::InvalidCredential)?
        }
        _ => sig.raw_rs.clone(),
    };
    dispatch_verify(
        issuer_crypto_alg,
        issuer_public_key,
        &canonical,
        normalized_signature.as_slice(),
    )
    .map_err(|_| VcError::InvalidCredential)?;

    // 3) Verify subject-private bundle (if present)
    if let Some(bundle) = subject_bundle {
        // Envelope hash must match
        if bundle.envelope_hash != envelope_hash {
            return Err(VcError::InvalidCredential);
        }

        // Issuer signature must match
        if bundle.issuer_signature != *sig {
            return Err(VcError::InvalidCredential);
        }

        // Verify Merkle openings
        verify_merkle_openings(&envelope.claims_commitment, bundle)?;
    }

    Ok(VerifyResult { envelope_hash })
}

// -----------------------------------------------------------------------------
// Merkle verification
// -----------------------------------------------------------------------------

fn verify_merkle_openings(
    commitment: &ClaimsCommitment,
    bundle: &SubjectPrivateBundle,
) -> Result<(), VcError> {
    let tree = &bundle.tree;
    let count = usize::try_from(tree.count).map_err(|_| VcError::InvalidCredential)?;
    let depth = usize::try_from(tree.depth).map_err(|_| VcError::InvalidCredential)?;
    if count == 0
        || count > MAX_COMMITMENT_CLAIMS
        || bundle.claims.len() > count
        || commitment.merkle_root.len() != 32
        || commitment.limits.salt_len < MIN_COMMITMENT_SALT_BYTES
        || commitment.limits.salt_len > MAX_COMMITMENT_SALT_BYTES
        || commitment.limits.max_value_len == 0
        || commitment.limits.max_value_len > MAX_COMMITMENT_VALUE_BYTES
    {
        return Err(VcError::InvalidCredential);
    }
    let padded_count = count
        .checked_next_power_of_two()
        .ok_or(VcError::InvalidCredential)?;
    let expected_depth =
        usize::try_from(padded_count.trailing_zeros()).map_err(|_| VcError::InvalidCredential)?;
    if depth != expected_depth {
        return Err(VcError::InvalidCredential);
    }

    let clm_tag = commitment.domain_tags.clm.as_bytes();
    let leaf_tag = commitment.domain_tags.leaf.as_bytes();
    let node_tag = commitment.domain_tags.node.as_bytes();

    let expected_salt_len =
        usize::try_from(commitment.limits.salt_len).map_err(|_| VcError::InvalidCredential)?;
    let mut observed_indices = BTreeSet::new();
    for opening in &bundle.claims {
        let value = &opening.value;
        let salt = &opening.salt;

        let max_value_len = usize::try_from(commitment.limits.max_value_len)
            .map_err(|_| VcError::InvalidCredential)?;
        let opening_index =
            usize::try_from(opening.index).map_err(|_| VcError::InvalidCredential)?;
        if value.len() > max_value_len
            || salt.len() != expected_salt_len
            || opening_index >= count
            || opening.merkle_path.len() != depth
            || !observed_indices.insert(opening.index)
        {
            return Err(VcError::InvalidCredential);
        }

        // Recompute inner digest
        let inner = claim_inner_digest(clm_tag, value, salt)?;

        // Recompute leaf digest
        let leaf = leaf_digest(leaf_tag, &opening.claim_path, &inner)?;

        // Walk Merkle path
        let mut h = leaf;
        let mut idx = opening_index;

        for sib in &opening.merkle_path {
            let sib_arr: [u8; 32] = sib
                .as_slice()
                .try_into()
                .map_err(|_| VcError::InvalidCredential)?;

            h = if idx & 1 == 0 {
                node_digest(node_tag, &h, &sib_arr)?
            } else {
                node_digest(node_tag, &sib_arr, &h)?
            };

            idx >>= 1;
        }

        if h.as_slice() != commitment.merkle_root {
            return Err(VcError::InvalidCredential);
        }
    }

    Ok(())
}

/// Verify Merkle openings only (no signature verification).
///
/// This checks:
/// - envelope hash consistency
/// - Merkle path correctness
///
/// It does NOT:
/// - verify issuer signature
/// - check issuer algorithm
pub fn verify_merkle_only(
    envelope: &CredentialEnvelope,
    bundle: &SubjectPrivateBundle,
) -> Result<(), VcError> {
    // Canonical CBOR bytes
    let canonical = canonical_credential_bytes(envelope).map_err(|_| VcError::Canonicalization)?;

    let envelope_hash = sha256(&canonical);

    // Envelope hash must match
    if bundle.envelope_hash != envelope_hash {
        return Err(VcError::InvalidCredential);
    }

    // Issuer signature bytes must match (consistency, not crypto)
    if bundle.issuer_signature != envelope.issuer_signature {
        return Err(VcError::InvalidCredential);
    }

    // Verify Merkle openings
    verify_merkle_openings(&envelope.claims_commitment, bundle)?;

    Ok(())
}

// -----------------------------------------------------------------------------
// Hash helpers (must match issue.rs)
// -----------------------------------------------------------------------------

fn sha256(data: &[u8]) -> [u8; 32] {
    sha2_256_digest(data).into_bytes()
}

fn claim_inner_digest(clm_tag: &[u8], value: &[u8], salt: &[u8]) -> Result<[u8; 32], VcError> {
    let value_len = u64::try_from(value.len()).map_err(|_| VcError::InvalidCredential)?;
    let encoded_len = value_len.to_be_bytes();
    sha256_parts(&[clm_tag, encoded_len.as_slice(), value, salt])
}

fn leaf_digest(leaf_tag: &[u8], claim_path: &str, inner: &[u8; 32]) -> Result<[u8; 32], VcError> {
    let name_hash = sha256(claim_path.as_bytes());
    sha256_parts(&[leaf_tag, name_hash.as_slice(), inner])
}

fn node_digest(node_tag: &[u8], left: &[u8; 32], right: &[u8; 32]) -> Result<[u8; 32], VcError> {
    sha256_parts(&[node_tag, left, right])
}

fn sha256_parts(parts: &[&[u8]]) -> Result<[u8; 32], VcError> {
    let capacity = parts.iter().try_fold(0_usize, |total, part| {
        total
            .checked_add(part.len())
            .ok_or(VcError::InvalidCredential)
    })?;
    let mut input = Zeroizing::new(Vec::with_capacity(capacity));
    for part in parts {
        input.extend_from_slice(part);
    }
    Ok(sha2_256_digest(&input).into_bytes())
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

fn issuer_credential_algorithm(
    a: CryptoAlg,
) -> Result<crate::committed::model::CredentialAlgorithm, VcError> {
    match a {
        CryptoAlg::P256 => Ok(crate::committed::model::CredentialAlgorithm::P256),
        CryptoAlg::Secp256k1 => Ok(crate::committed::model::CredentialAlgorithm::Secp256k1),
        CryptoAlg::Ed25519 => Ok(crate::committed::model::CredentialAlgorithm::Ed25519),
        _ => Err(VcError::UnsupportedProfile),
    }
}
