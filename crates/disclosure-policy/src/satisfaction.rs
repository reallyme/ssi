// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::{RequiredClaim, VpPolicy, VpPolicyError};
use reallyme_vp_core::DisclosureMode;

/// A single semantic input the OpenID4VP format layer must turn into circuit
/// public inputs and witness material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DerivationInput {
    /// Canonical claim path from policy.
    pub claim_path: String,

    /// Disclosure operation a proof mechanism must prove for this claim.
    pub mode: DisclosureMode,
}

/// Derivation plan selected by policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DerivationPlan {
    /// Semantic claim constraints a protocol format may derive.
    pub inputs: Vec<DerivationInput>,
}

/// How a verifier request can be satisfied before format-specific proof work.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SatisfactionPlan {
    /// Satisfy the request by disclosing credential claims.
    Disclose(Vec<RequiredClaim>),

    /// Satisfy the request by deriving semantic claims in a protocol layer.
    Derive(DerivationPlan),
}

/// Select a disclosure-or-derivation plan for a policy.
///
/// This function identifies semantic derivation requirements only. A protocol
/// format layer is responsible for selecting a proof system and proving
/// capability that can satisfy every requested operation.
pub fn plan_satisfaction(policy: &VpPolicy) -> Result<SatisfactionPlan, VpPolicyError> {
    if !requires_derivation(&policy.required_claims) {
        return Ok(SatisfactionPlan::Disclose(policy.required_claims.clone()));
    }

    if !policy.allow_zk {
        return Err(VpPolicyError::ZkDerivationUnavailable);
    }

    Ok(SatisfactionPlan::Derive(DerivationPlan {
        inputs: policy
            .required_claims
            .iter()
            .map(|claim| DerivationInput {
                claim_path: claim.claim_path.clone(),
                mode: claim.mode,
            })
            .collect(),
    }))
}

fn requires_derivation(claims: &[RequiredClaim]) -> bool {
    claims
        .iter()
        .any(|claim| !matches!(claim.mode, DisclosureMode::Reveal))
}
