// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use identity_core_primitives::Algorithm;
use reallyme_vp_core::DisclosureMode;
use serde::{Deserialize, Serialize};

/// Verifier policy definition.
///
/// The structure is intentionally explicit: every field corresponds to a
/// possible accept/reject decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VpPolicy {
    /// Allowed issuer signature algorithms.
    pub allowed_issuer_algorithms: Vec<Algorithm>,

    /// Allowed holder binding algorithms.
    pub allowed_holder_algorithms: Vec<Algorithm>,

    /// Whether SD-JWT VC presentations are allowed.
    pub allow_sd_jwt: bool,

    /// Whether zero-knowledge presentations are allowed.
    pub allow_zk: bool,

    /// Whether mdoc presentations are allowed at the VP policy layer.
    pub allow_mdoc: bool,

    /// Required claims and their disclosure modes.
    pub required_claims: Vec<RequiredClaim>,

    /// Optional allow-list of credential claimset identifiers.
    pub allowed_claimsets: Option<Vec<String>>,

    /// Whether credential status must be checked.
    pub require_status: bool,

    /// Maximum allowed age, in seconds, of the resolved status information.
    pub max_status_age_seconds: Option<u64>,

    /// Whether QEAA compliance evidence must be present and verified.
    pub require_qeaa: bool,

    /// Minimum accepted QEAA profile identifier.
    pub min_qeaa_profile: Option<String>,

    /// Minimum accepted identity proofing rank.
    pub min_identity_proofing_level: Option<u32>,
}

impl Default for VpPolicy {
    fn default() -> Self {
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
            allow_mdoc: false,
            required_claims: Vec::new(),
            allowed_claimsets: None,
            require_status: true,
            max_status_age_seconds: None,
            require_qeaa: false,
            min_qeaa_profile: None,
            min_identity_proofing_level: None,
        }
    }
}

impl VpPolicy {
    /// Policy for local development and interoperability testing.
    pub fn dev_default() -> Self {
        Self {
            require_status: false,
            ..Self::default()
        }
    }

    /// Extremely permissive policy intended for tests only.
    pub fn unsafe_permissive_for_tests() -> Self {
        Self {
            allowed_issuer_algorithms: vec![
                Algorithm::Ed25519,
                Algorithm::P256,
                Algorithm::Secp256k1,
                Algorithm::MlDsa87,
            ],
            require_status: false,
            ..Self::default()
        }
    }

    /// Add a required claim constraint.
    pub fn require_claim(mut self, claim_path: impl Into<String>, mode: DisclosureMode) -> Self {
        self.required_claims.push(RequiredClaim {
            claim_path: claim_path.into(),
            mode,
        });
        self
    }
}

/// A single required claim constraint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequiredClaim {
    /// Canonical claim path.
    pub claim_path: String,

    /// Required disclosure mode.
    pub mode: DisclosureMode,
}
