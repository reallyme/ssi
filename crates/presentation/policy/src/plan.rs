// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::{
    error::VpPolicyError,
    model::{RequiredClaim, VpPolicy},
};
use identity_credential_claims_core::DisclosureMode;

/// Policy-level plan for satisfying a verifier request.
///
/// Policy only decides whether derivation is possible. It never invokes a prover.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SatisfactionPlan {
    /// The wallet must disclose the listed claims.
    Disclose(Vec<RequiredClaim>),
    /// A protocol layer may derive the requested semantic statements.
    Derive(DerivationPlan),
}

/// Derivation plan selected by policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DerivationPlan {
    /// Claim material the wallet must normalize into prover inputs.
    pub inputs: Vec<DerivationInput>,
}

/// Claim input required to derive a policy statement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DerivationInput {
    /// Stable claim path from the policy requirement.
    pub claim_path: String,
    /// Disclosure predicate a proof mechanism must satisfy for this claim.
    pub mode: DisclosureMode,
}

/// Chooses disclosure or derivation for a policy without invoking a prover.
pub fn plan_satisfaction(policy: &VpPolicy) -> Result<SatisfactionPlan, VpPolicyError> {
    if !requires_derivation(policy.required_claims.as_slice()) {
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
