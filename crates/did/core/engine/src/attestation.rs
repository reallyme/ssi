// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use serde::{Deserialize, Serialize};

/// Core attestation over a canonical DID core snapshot.
///
/// This corresponds to TS `Attestation` produced in step 5
/// of `createEngine`, but WITHOUT envelopes.
///
/// - One per signing verification method
/// - Signature is over canonical CBOR bytes
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CoreAttestation {
    /// Algorithm used to produce the signature
    pub algorithm: String,

    /// Verification method ID (e.g. "#ed25519")
    pub verification_method: String,

    /// Base64url-encoded signature bytes
    pub signature: String,
}
