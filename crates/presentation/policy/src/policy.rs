// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use identity_core_primitives::Algorithm;
use identity_credential_claims_core::DisclosureMode;

use crate::model::{RequiredClaim, VpPolicy};
use crate::VpPolicyError;

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
    /// Add a required claim constraint.
    ///
    /// Predicate modes require an explicit operand and are rejected here.
    pub fn require_claim(
        mut self,
        claim_path: impl Into<String>,
        mode: DisclosureMode,
    ) -> Result<Self, VpPolicyError> {
        if !matches!(mode, DisclosureMode::Hidden | DisclosureMode::Reveal) {
            return Err(VpPolicyError::PolicyMisconfiguration);
        }
        self.required_claims.push(RequiredClaim {
            claim_path: claim_path.into(),
            mode,
            operand: crate::PredicateOperand::None,
        });
        Ok(self)
    }

    /// Add a numeric threshold predicate requirement.
    pub fn require_threshold_claim(
        mut self,
        claim_path: impl Into<String>,
        mode: DisclosureMode,
        threshold: u64,
    ) -> Result<Self, VpPolicyError> {
        if !matches!(mode, DisclosureMode::Gte | DisclosureMode::Lte) {
            return Err(VpPolicyError::PolicyMisconfiguration);
        }
        self.required_claims.push(RequiredClaim {
            claim_path: claim_path.into(),
            mode,
            operand: crate::PredicateOperand::Threshold(threshold),
        });
        Ok(self)
    }
}
