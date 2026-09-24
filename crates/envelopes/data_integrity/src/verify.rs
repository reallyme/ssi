// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_did_types::DIDDocument;

use crate::proof::{DataIntegrityCryptosuite, DataIntegrityProofError};
use crate::suites::es256_jws_cid_2025::verify_es256_jws_cid_2025;

/// Input for verifying a Data Integrity proof with a supported cryptosuite.
#[derive(Debug, Clone, Copy)]
pub struct DataIntegrityVerifyInput<'a> {
    /// Cryptosuite to apply.
    pub cryptosuite: DataIntegrityCryptosuite,

    /// DID document carrying the proof and verification method material.
    pub document: &'a DIDDocument,
}

/// Verify a Data Integrity proof with a supported cryptosuite.
///
/// This low-level function proves only that a key referenced by the supplied
/// document signed that document's own content identifier. It does not establish
/// controller authority, trust, or document authenticity by itself. Consumers
/// must use the composed DID-document verification pipeline when making an
/// authenticity or authorization decision.
pub fn verify_data_integrity_proof(
    input: &DataIntegrityVerifyInput<'_>,
) -> Result<(), DataIntegrityProofError> {
    match input.cryptosuite {
        DataIntegrityCryptosuite::Es256JwsCid2025 => {
            verify_es256_jws_cid_2025(input.document).map_err(DataIntegrityProofError::from)
        }
    }
}
