// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_did_types::DataIntegrityProof;

use crate::proof::{DataIntegrityCryptosuite, DataIntegrityProofError};
use crate::suites::es256_jws_cid_2025::sign_es256_jws_cid_2025;

/// Input for creating a Data Integrity proof with a supported cryptosuite.
#[derive(Debug, Clone, Copy)]
pub struct DataIntegritySignInput<'a> {
    /// Cryptosuite to apply.
    pub cryptosuite: DataIntegrityCryptosuite,

    /// did:me current core CID signed by `es256-jws-cid-2025`.
    pub current_core: &'a str,

    /// Private signing key bytes owned by the caller.
    pub secret_key: &'a [u8],

    /// Verification method reference embedded in the proof.
    pub verification_method: &'a str,

    /// Creation timestamp string embedded in the proof.
    pub created: &'a str,
}

/// Create a Data Integrity proof with a supported cryptosuite.
pub fn sign_data_integrity_proof(
    input: &DataIntegritySignInput<'_>,
) -> Result<DataIntegrityProof, DataIntegrityProofError> {
    if input.secret_key.is_empty()
        || input.verification_method.is_empty()
        || input.created.is_empty()
        || input.current_core.is_empty()
    {
        return Err(DataIntegrityProofError::InvalidInput);
    }

    match input.cryptosuite {
        DataIntegrityCryptosuite::Es256JwsCid2025 => sign_es256_jws_cid_2025(
            input.current_core,
            input.secret_key,
            input.verification_method,
            input.created,
        )
        .map_err(DataIntegrityProofError::from),
    }
}
