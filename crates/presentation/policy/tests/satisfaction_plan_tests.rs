// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::print_stderr
)]
//! Tests for VP policy satisfaction planning.

use identity_credential_claims_core::DisclosureMode;
use identity_presentation_vp_policy::{
    plan_satisfaction, PredicateOperand, RequiredClaim, SatisfactionPlan, VpPolicy, VpPolicyError,
};

fn test_policy() -> VpPolicy {
    VpPolicy {
        require_status: false,
        ..VpPolicy::default()
    }
}

#[test]
fn planner_returns_semantic_inputs_without_selecting_a_circuit() {
    let policy = test_policy()
        .require_threshold_claim("/claims/age", DisclosureMode::Gte, 18)
        .expect("valid threshold requirement")
        .require_claim("/claims/family_name", DisclosureMode::Reveal)
        .expect("valid reveal requirement");

    let plan = plan_satisfaction(&policy).unwrap();

    match plan {
        SatisfactionPlan::Derive(derivation) => {
            assert_eq!(derivation.inputs.len(), 2);
            assert_eq!(derivation.inputs[0].claim_path, "/claims/age");
            assert_eq!(derivation.inputs[0].mode, DisclosureMode::Gte);
            assert_eq!(
                derivation.inputs[0].operand,
                PredicateOperand::Threshold(18)
            );
            assert_eq!(derivation.inputs[1].claim_path, "/claims/family_name");
            assert_eq!(derivation.inputs[1].mode, DisclosureMode::Reveal);
        }
        SatisfactionPlan::Disclose(_) => panic!("expected derivation plan"),
    }
}

#[test]
fn planner_discloses_when_only_reveal_claims_are_required() {
    let policy = test_policy()
        .require_claim("/claims/family_name", DisclosureMode::Reveal)
        .expect("valid reveal requirement");

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
    let mut policy = test_policy();
    policy.required_claims.push(RequiredClaim {
        claim_path: "/claims/age".into(),
        mode: DisclosureMode::MemberOfSet,
        operand: PredicateOperand::Set(vec![b"18".to_vec(), b"21".to_vec()]),
    });

    let plan = plan_satisfaction(&policy).unwrap();

    match plan {
        SatisfactionPlan::Derive(derivation) => {
            assert_eq!(derivation.inputs.len(), 1);
            assert_eq!(derivation.inputs[0].claim_path, "/claims/age");
            assert_eq!(derivation.inputs[0].mode, DisclosureMode::MemberOfSet);
            assert_eq!(
                derivation.inputs[0].operand,
                PredicateOperand::Set(vec![b"18".to_vec(), b"21".to_vec()])
            );
        }
        SatisfactionPlan::Disclose(_) => panic!("expected derivation plan"),
    }
}

#[test]
fn planner_rejects_when_zk_is_not_allowed_for_derived_claims() {
    let mut policy = test_policy()
        .require_threshold_claim("/claims/age", DisclosureMode::Gte, 18)
        .expect("valid threshold requirement");
    policy.allow_zk = false;

    let err = plan_satisfaction(&policy).unwrap_err();

    assert_eq!(err, VpPolicyError::ZkDerivationUnavailable);
}
