// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::print_stderr
)]
//! Tests for VP policy satisfaction planning.

use identity_credential_claims_core::DisclosureMode;
use identity_presentation_vp_policy::{
    plan_satisfaction, SatisfactionPlan, VpPolicy, VpPolicyError,
};

#[test]
fn planner_returns_semantic_inputs_without_selecting_a_circuit() {
    let policy = VpPolicy::dev_default()
        .require_claim("/claims/age", DisclosureMode::Gte)
        .require_claim("/claims/family_name", DisclosureMode::Reveal);

    let plan = plan_satisfaction(&policy).unwrap();

    match plan {
        SatisfactionPlan::Derive(derivation) => {
            assert_eq!(derivation.inputs.len(), 2);
            assert_eq!(derivation.inputs[0].claim_path, "/claims/age");
            assert_eq!(derivation.inputs[0].mode, DisclosureMode::Gte);
            assert_eq!(derivation.inputs[1].claim_path, "/claims/family_name");
            assert_eq!(derivation.inputs[1].mode, DisclosureMode::Reveal);
        }
        SatisfactionPlan::Disclose(_) => panic!("expected derivation plan"),
    }
}

#[test]
fn planner_discloses_when_only_reveal_claims_are_required() {
    let policy =
        VpPolicy::dev_default().require_claim("/claims/family_name", DisclosureMode::Reveal);

    let plan = plan_satisfaction(&policy).unwrap();

    match plan {
        SatisfactionPlan::Disclose(claims) => {
            assert_eq!(claims.len(), 1);
            assert_eq!(claims[0].mode, DisclosureMode::Reveal);
        }
        SatisfactionPlan::Derive(_) => panic!("expected disclosure plan"),
    }
}

#[test]
fn planner_preserves_proof_system_neutral_predicates() {
    let policy = VpPolicy::dev_default().require_claim("/claims/age", DisclosureMode::MemberOfSet);

    let plan = plan_satisfaction(&policy).unwrap();

    match plan {
        SatisfactionPlan::Derive(derivation) => {
            assert_eq!(derivation.inputs.len(), 1);
            assert_eq!(derivation.inputs[0].claim_path, "/claims/age");
            assert_eq!(derivation.inputs[0].mode, DisclosureMode::MemberOfSet);
        }
        SatisfactionPlan::Disclose(_) => panic!("expected derivation plan"),
    }
}

#[test]
fn planner_rejects_when_zk_is_not_allowed_for_derived_claims() {
    let mut policy = VpPolicy::dev_default().require_claim("/claims/age", DisclosureMode::Gte);
    policy.allow_zk = false;

    let err = plan_satisfaction(&policy).unwrap_err();

    assert_eq!(err, VpPolicyError::ZkDerivationUnavailable);
}
