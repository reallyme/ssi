// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

// age.rs
use crate::{PredicateOperand, RequiredClaim, VpPolicy};
use identity_core_primitives::Algorithm;

/// Build the baseline verifier policy for an EU age credential presentation.
///
/// This baseline selects trust, status, algorithm, and format requirements but
/// intentionally requests no age fact. Use [`eu_age_over_policy`] when the
/// relying party needs a concrete age predicate.
pub fn eu_age_policy() -> VpPolicy {
    VpPolicy {
        require_status: false, // often ephemeral

        require_qeaa: false,
        min_qeaa_profile: None,
        min_identity_proofing_level: None,

        allowed_issuer_algorithms: vec![Algorithm::P256, Algorithm::Ed25519],
        allowed_holder_algorithms: vec![Algorithm::P256, Algorithm::Ed25519],

        allow_sd_jwt: true,
        allow_zk: true, // strongly recommended

        // Only credentials of this claimset satisfy this profile.
        allowed_claimsets: Some(vec!["eu.age.v1".into()]),

        ..VpPolicy::default()
    }
}

/// Build an EU age policy that requires proof of the supplied minimum age.
pub fn eu_age_over_policy(minimum_age: u64) -> VpPolicy {
    let mut policy = eu_age_policy();
    policy.required_claims.push(RequiredClaim {
        claim_path: "/claims/age".into(),
        mode: identity_credential_claims_core::DisclosureMode::Gte,
        operand: PredicateOperand::Threshold(minimum_age),
    });
    policy
}
