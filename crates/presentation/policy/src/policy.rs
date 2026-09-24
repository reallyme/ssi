// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use identity_core_primitives::Algorithm;
use identity_credential_claims_core::DisclosureMode;

use crate::model::{RequiredClaim, VpPolicy};

/// ----------------------------------------------------------------
/// Default verifier policy (trait-based, idiomatic Rust)
/// ----------------------------------------------------------------
impl Default for VpPolicy {
    fn default() -> Self {
        Self {
            // -----------------------------------------------------------------
            // Cryptography
            // -----------------------------------------------------------------
            allowed_issuer_algorithms: vec![
                Algorithm::Ed25519,
                Algorithm::P256,
                Algorithm::Secp256k1,
            ],
            allowed_holder_algorithms: vec![
                Algorithm::Ed25519,
                Algorithm::P256,
                Algorithm::Secp256k1,
            ],

            // -----------------------------------------------------------------
            // Presentation formats
            // -----------------------------------------------------------------
            allow_sd_jwt: true,
            allow_zk: true,

            // -----------------------------------------------------------------
            // Claims
            // -----------------------------------------------------------------
            required_claims: Vec::new(),
            allowed_claimsets: None,

            // -----------------------------------------------------------------
            // Status / revocation
            // -----------------------------------------------------------------
            require_status: true,
            max_status_age_seconds: None,

            // -----------------------------------------------------------------
            // QEAA / audit
            // -----------------------------------------------------------------
            require_qeaa: false,
            min_qeaa_profile: None,
            min_identity_proofing_level: None,
        }
    }
}

/// ----------------------------------------------------------------
/// Additional constructors & helpers
/// ----------------------------------------------------------------
impl VpPolicy {
    /// Permissive policy intended for local development and wallet interoperability testing.
    ///
    /// - Allows SD-JWT and ZK
    /// - Does NOT require status checks
    /// - Does NOT require QEAA
    pub fn dev_default() -> Self {
        Self {
            allowed_issuer_algorithms: vec![
                Algorithm::Ed25519,
                Algorithm::P256,
                Algorithm::Secp256k1,
            ],
            allowed_holder_algorithms: vec![
                Algorithm::Ed25519,
                Algorithm::P256,
                Algorithm::Secp256k1,
            ],

            allow_sd_jwt: true,
            allow_zk: true,

            required_claims: Vec::new(),
            allowed_claimsets: None,

            require_status: false,
            max_status_age_seconds: None,

            require_qeaa: false,
            min_qeaa_profile: None,
            min_identity_proofing_level: None,
        }
    }

    /// Extremely permissive policy intended for tests only.
    ///
    /// Must not be used in production.
    pub fn unsafe_permissive_for_tests() -> Self {
        Self {
            allowed_issuer_algorithms: vec![
                Algorithm::Ed25519,
                Algorithm::P256,
                Algorithm::Secp256k1,
                Algorithm::MlDsa87,
            ],
            allowed_holder_algorithms: vec![
                Algorithm::Ed25519,
                Algorithm::P256,
                Algorithm::Secp256k1,
            ],

            allow_sd_jwt: true,
            allow_zk: true,

            required_claims: Vec::new(),
            allowed_claimsets: None,

            require_status: false,
            max_status_age_seconds: None,

            require_qeaa: false,
            min_qeaa_profile: None,
            min_identity_proofing_level: None,
        }
    }

    /// Add a required claim constraint.
    ///
    /// Example:
    /// policy.require_claim("/claims/age", DisclosureMode::Gte)
    pub fn require_claim(mut self, claim_path: impl Into<String>, mode: DisclosureMode) -> Self {
        self.required_claims.push(RequiredClaim {
            claim_path: claim_path.into(),
            mode,
        });
        self
    }
}
