// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use core::fmt;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::error::IetfSdJwtVcError;

/// Namespaced extension claim used by Me Profile to bind SD-JWT artifacts
/// to an external Merkle commitment used by ZK proof flows.
pub const ME_PROFILE_EXTENSION_CLAIM: &str = "me_zk";
const MERKLE_ROOT_LEN: usize = 32;
const MERKLE_ROOT_B64U_LEN: usize = 43;
const MAX_COMMITMENT_ALGORITHM_BYTES: usize = 64;

#[derive(Serialize, Deserialize, PartialEq, Eq)]
pub struct MeProfileMerkleBinding {
    /// base64url(32-byte Merkle root)
    pub merkle_root_b64u: String,
    /// Hash algorithm identifier for the Merkle tree commitment.
    pub commitment_alg: String,
}

impl fmt::Debug for MeProfileMerkleBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MeProfileMerkleBinding([REDACTED])")
    }
}

impl Zeroize for MeProfileMerkleBinding {
    fn zeroize(&mut self) {
        self.merkle_root_b64u.zeroize();
        self.commitment_alg.zeroize();
    }
}

impl Drop for MeProfileMerkleBinding {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for MeProfileMerkleBinding {}

impl MeProfileMerkleBinding {
    pub fn new(
        merkle_root_b64u: impl Into<String>,
        commitment_alg: impl Into<String>,
    ) -> Result<Self, IetfSdJwtVcError> {
        let binding = Self {
            merkle_root_b64u: merkle_root_b64u.into(),
            commitment_alg: commitment_alg.into(),
        };
        validate_merkle_binding(&binding)?;
        Ok(binding)
    }
}

pub fn insert_me_profile_merkle_binding(
    payload: &mut Map<String, Value>,
    binding: &MeProfileMerkleBinding,
) -> Result<(), IetfSdJwtVcError> {
    if payload.contains_key(ME_PROFILE_EXTENSION_CLAIM) {
        return Err(IetfSdJwtVcError::InvalidInput);
    }
    validate_merkle_binding(binding)?;

    payload.insert(
        ME_PROFILE_EXTENSION_CLAIM.to_string(),
        serde_json::json!({
            "merkle_root": binding.merkle_root_b64u,
            "alg": binding.commitment_alg,
        }),
    );
    Ok(())
}

pub fn extract_me_profile_merkle_binding(
    payload: &Map<String, Value>,
) -> Result<Option<MeProfileMerkleBinding>, IetfSdJwtVcError> {
    let Some(value) = payload.get(ME_PROFILE_EXTENSION_CLAIM) else {
        return Ok(None);
    };

    let obj = value.as_object().ok_or(IetfSdJwtVcError::InvalidInput)?;
    let merkle_root = obj
        .get("merkle_root")
        .and_then(Value::as_str)
        .ok_or(IetfSdJwtVcError::InvalidInput)?;
    let algorithm = obj
        .get("alg")
        .and_then(Value::as_str)
        .ok_or(IetfSdJwtVcError::InvalidInput)?;
    validate_merkle_binding_values(merkle_root, algorithm)?;

    let binding = MeProfileMerkleBinding {
        merkle_root_b64u: merkle_root.to_owned(),
        commitment_alg: algorithm.to_owned(),
    };
    validate_merkle_binding(&binding)?;
    Ok(Some(binding))
}

/// Verify that an IETF SD-JWT VC payload is bound to the expected ReallyMe
/// claim commitment root.
///
/// Standard SD-JWT verifiers can ignore `me_zk`; ReallyMe verifiers use this
/// check before accepting Merkle openings or ZK proofs derived from the
/// credential's committed claim set.
pub fn verify_me_profile_merkle_binding(
    payload: &Map<String, Value>,
    expected_merkle_root: &[u8],
    expected_commitment_alg: &str,
) -> Result<MeProfileMerkleBinding, IetfSdJwtVcError> {
    if expected_merkle_root.len() != MERKLE_ROOT_LEN || expected_commitment_alg.trim().is_empty() {
        return Err(IetfSdJwtVcError::InvalidInput);
    }

    let binding =
        extract_me_profile_merkle_binding(payload)?.ok_or(IetfSdJwtVcError::Verification)?;
    if binding.commitment_alg != expected_commitment_alg {
        return Err(IetfSdJwtVcError::Verification);
    }

    let root = Zeroizing::new(
        codec_base64url::base64url_to_bytes(binding.merkle_root_b64u.as_str())
            .map_err(|_| IetfSdJwtVcError::InvalidInput)?,
    );
    if root.as_slice() != expected_merkle_root {
        return Err(IetfSdJwtVcError::Verification);
    }

    Ok(binding)
}

fn validate_merkle_binding(binding: &MeProfileMerkleBinding) -> Result<(), IetfSdJwtVcError> {
    validate_merkle_binding_values(&binding.merkle_root_b64u, &binding.commitment_alg)?;
    let root = Zeroizing::new(
        codec_base64url::base64url_to_bytes(binding.merkle_root_b64u.as_str())
            .map_err(|_| IetfSdJwtVcError::InvalidInput)?,
    );
    if root.len() != MERKLE_ROOT_LEN {
        return Err(IetfSdJwtVcError::InvalidInput);
    }
    Ok(())
}

fn validate_merkle_binding_values(
    merkle_root_b64u: &str,
    commitment_alg: &str,
) -> Result<(), IetfSdJwtVcError> {
    if merkle_root_b64u.len() != MERKLE_ROOT_B64U_LEN
        || commitment_alg.trim().is_empty()
        || commitment_alg.len() > MAX_COMMITMENT_ALGORITHM_BYTES
    {
        return Err(IetfSdJwtVcError::InvalidInput);
    }
    Ok(())
}
