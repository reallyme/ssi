// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::canonical::Canonical;
use crate::core::DidCore;
use crate::error::{CanonicalStateViolation, DidCoreError};

use reallyme_codec::cbor::{compute_cid_dag_cbor, verify_dag_cbor_cid};

/// Compute the CID (CIDv1, dag-cbor, sha2-256) for a DID core object.
///
/// Mirrors TS `computeCidDagCbor(coreCBOR)`.
pub fn compute_core_cid(core: &DidCore) -> Result<String, DidCoreError> {
    let bytes = core.canonical_cbor()?;
    if bytes.is_empty() {
        return Err(DidCoreError::InvalidCanonicalState(
            CanonicalStateViolation::EmptyCoreCbor,
        ));
    }
    Ok(compute_cid_dag_cbor(&bytes))
}

/// Verify that a CID matches the DID core object.
///
/// Returns:
/// (ok, expected_cid, actual_cid)
pub fn verify_core_cid(cid: &str, core: &DidCore) -> Result<(bool, String, String), DidCoreError> {
    let bytes = core.canonical_cbor()?;
    if bytes.is_empty() {
        return Err(DidCoreError::InvalidCanonicalState(
            CanonicalStateViolation::EmptyCoreCbor,
        ));
    }
    Ok(verify_dag_cbor_cid(cid, &bytes))
}
