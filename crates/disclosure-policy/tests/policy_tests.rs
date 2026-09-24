// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Test coverage for this crate.
#![allow(missing_docs)]
#![allow(clippy::panic)]
#![allow(clippy::unwrap_used)]

use identity_core_primitives::Algorithm;
use reallyme_credential_claims::profiles::{
    eu_address_v1, eu_age_v1, eu_company_v1, eu_diploma_v1, eu_driving_license_v1, eu_eaa_v1,
    eu_eidas_vid_v1, eu_health_v1, eu_passport_v1, eu_pid_v1, eu_professional_license_v1,
    eu_tax_v1,
};
use reallyme_credential_claims::ClaimsRegistry;
use reallyme_disclosure_policy::{
    evaluate, plan_satisfaction, policy_for_claimset, validate_policy_claims_against_registry,
    EvaluationContext, ExtractedDisclosure, PolicyDecision, QeaaContext, SatisfactionPlan,
    StatusContext, VpPolicy, VpPolicyError,
};
use reallyme_vp_core::{DisclosureMode, Presentation, SdJwtVcPresentation};

struct RegistryPolicyCase {
    claimset_id: &'static str,
    registry: fn() -> ClaimsRegistry,
    claim_path: &'static str,
    mode: DisclosureMode,
}

fn sd_jwt_presentation() -> Presentation {
    Presentation::SdJwtVc(Box::new(SdJwtVcPresentation {
        sd_jwt: "header.payload.signature".into(),
        disclosures: vec![],
        kb_jwt: Some("kb.header.payload.signature".into()),
        vct: Some("eu.pid.v1".into()),
        envelope_hash: None,
    }))
}

#[test]
fn selector_covers_all_eidas_profiles() {
    let ids = [
        "eu.pid.v1",
        "eu.pid.baseline.v1",
        "eu.eaa.v1",
        "eu.address.v1",
        "eu.age.v1",
        "eu.diploma.v1",
        "eu.driving_license.v1",
        "eu.professional_license.v1",
        "eu.passport.v1",
        "eu.health.v1",
        "eu.kyc.v1",
        "eu.company.v1",
        "eu.tax.v1",
        "eu.eidas-vid.v1",
    ];

    for id in ids {
        assert!(policy_for_claimset(id).is_some(), "missing policy for {id}");
    }

    assert!(policy_for_claimset("unknown").is_none());
}

#[test]
fn pid_policy_accepts_valid_qeaa_sd_jwt_context() {
    let policy = policy_for_claimset("eu.pid.v1")
        .unwrap()
        .require_claim("/claims/family_name", DisclosureMode::Reveal);
    let presentation = sd_jwt_presentation();
    let disclosures = [ExtractedDisclosure {
        claim_path: "/claims/family_name".into(),
        mode: DisclosureMode::Reveal,
    }];

    let decision = evaluate(
        &policy,
        &EvaluationContext {
            binding_ok: true,
            now_unix: 1_700_000_000,
            presentation: &presentation,
            issuer_algorithm: Algorithm::P256,
            holder_algorithm: Algorithm::P256,
            claimset_id: "eu.pid.v1",
            disclosures: &disclosures,
            status: Some(StatusContext {
                checked: true,
                revoked: false,
                suspended: false,
                age_seconds: Some(3_600),
            }),
            qeaa: Some(QeaaContext {
                verified: true,
                profile: Some("QEAA-ETSI-1.0"),
                identity_proofing_rank: Some(3),
            }),
        },
    );

    assert_eq!(decision, PolicyDecision::Accept);
}

#[test]
fn pid_policy_rejects_missing_qeaa_and_stale_status() {
    let policy = policy_for_claimset("eu.pid.v1").unwrap();
    let presentation = sd_jwt_presentation();

    let decision = evaluate(
        &policy,
        &EvaluationContext {
            binding_ok: true,
            now_unix: 1_700_000_000,
            presentation: &presentation,
            issuer_algorithm: Algorithm::P256,
            holder_algorithm: Algorithm::P256,
            claimset_id: "eu.pid.v1",
            disclosures: &[],
            status: Some(StatusContext {
                checked: true,
                revoked: false,
                suspended: false,
                age_seconds: Some(172_800),
            }),
            qeaa: None,
        },
    );

    match decision {
        PolicyDecision::Reject(errors) => {
            assert!(errors.contains(&VpPolicyError::StatusTooOld));
            assert!(errors.contains(&VpPolicyError::QeaaRequired));
        }
        PolicyDecision::Accept => panic!("expected policy rejection"),
    }
}

#[test]
fn passport_policy_rejects_sd_jwt() {
    let policy = policy_for_claimset("eu.passport.v1").unwrap();
    let presentation = sd_jwt_presentation();

    let decision = evaluate(
        &policy,
        &EvaluationContext {
            binding_ok: true,
            now_unix: 1_700_000_000,
            presentation: &presentation,
            issuer_algorithm: Algorithm::P256,
            holder_algorithm: Algorithm::P256,
            claimset_id: "eu.passport.v1",
            disclosures: &[],
            status: Some(StatusContext {
                checked: true,
                revoked: false,
                suspended: false,
                age_seconds: Some(60),
            }),
            qeaa: Some(QeaaContext {
                verified: true,
                profile: Some("QEAA-ETSI-1.0"),
                identity_proofing_rank: Some(3),
            }),
        },
    );

    match decision {
        PolicyDecision::Reject(errors) => {
            assert!(errors.contains(&VpPolicyError::PresentationFormatNotAllowed));
        }
        PolicyDecision::Accept => panic!("expected policy rejection"),
    }
}

#[test]
fn policy_plans_disclosure_for_revealed_claims() {
    let policy = policy_for_claimset("eu.pid.v1")
        .unwrap()
        .require_claim("/claims/family_name", DisclosureMode::Reveal);

    let plan = plan_satisfaction(&policy).unwrap();

    match plan {
        SatisfactionPlan::Disclose(claims) => {
            assert_eq!(claims.len(), 1);
            assert_eq!(claims[0].claim_path, "/claims/family_name");
        }
        SatisfactionPlan::Derive(_) => panic!("revealed claim should not require derivation"),
    }
}

#[test]
fn policy_emits_proof_system_neutral_predicate_plan() {
    let policy = policy_for_claimset("eu.age.v1")
        .unwrap()
        .require_claim("/claims/age", DisclosureMode::Gte);

    let plan = plan_satisfaction(&policy).unwrap();

    match plan {
        SatisfactionPlan::Derive(plan) => {
            assert_eq!(plan.inputs.len(), 1);
            assert_eq!(plan.inputs[0].claim_path, "/claims/age");
            assert_eq!(plan.inputs[0].mode, DisclosureMode::Gte);
        }
        SatisfactionPlan::Disclose(_) => panic!("predicate must require derivation"),
    }
}

#[test]
fn policy_required_claims_validate_against_claim_registry() {
    let policy = policy_for_claimset("eu.pid.v1")
        .unwrap()
        .require_claim("/claims/family_name", DisclosureMode::Reveal);

    assert!(validate_policy_claims_against_registry(&policy, &eu_pid_v1()).is_ok());
}

#[test]
fn policy_required_claim_preflight_rejects_unknown_claims() {
    let policy = policy_for_claimset("eu.pid.v1")
        .unwrap()
        .require_claim("/claims/unregistered", DisclosureMode::Reveal);

    let err = validate_policy_claims_against_registry(&policy, &eu_pid_v1()).unwrap_err();

    assert_eq!(err, VpPolicyError::RequiredClaimInvalid);
}

#[test]
fn policy_required_claim_preflight_rejects_disallowed_modes() {
    let policy = policy_for_claimset("eu.age.v1")
        .unwrap()
        .require_claim("/claims/age", DisclosureMode::MemberOfSet);

    let err = validate_policy_claims_against_registry(&policy, &eu_age_v1()).unwrap_err();

    assert_eq!(err, VpPolicyError::DisclosureModeNotAllowed);
}

#[test]
fn policy_required_claim_preflight_rejects_claimset_mismatch() {
    let policy = VpPolicy {
        allowed_claimsets: Some(vec!["eu.age.v1".into()]),
        ..VpPolicy::default()
    }
    .require_claim("/claims/family_name", DisclosureMode::Reveal);

    let err = validate_policy_claims_against_registry(&policy, &eu_pid_v1()).unwrap_err();

    assert_eq!(err, VpPolicyError::ClaimsetNotAllowed);
}

#[test]
fn predefined_policy_profiles_validate_representative_registry_claims() {
    let cases = [
        RegistryPolicyCase {
            claimset_id: "eu.pid.v1",
            registry: eu_pid_v1,
            claim_path: "/claims/family_name",
            mode: DisclosureMode::Reveal,
        },
        RegistryPolicyCase {
            claimset_id: "eu.age.v1",
            registry: eu_age_v1,
            claim_path: "/claims/age",
            mode: DisclosureMode::Gte,
        },
        RegistryPolicyCase {
            claimset_id: "eu.address.v1",
            registry: eu_address_v1,
            claim_path: "/claims/resident_address/street_address",
            mode: DisclosureMode::Reveal,
        },
        RegistryPolicyCase {
            claimset_id: "eu.eaa.v1",
            registry: eu_eaa_v1,
            claim_path: "/claims/subject_family_name",
            mode: DisclosureMode::Reveal,
        },
        RegistryPolicyCase {
            claimset_id: "eu.company.v1",
            registry: eu_company_v1,
            claim_path: "/claims/current_legal_name",
            mode: DisclosureMode::Reveal,
        },
        RegistryPolicyCase {
            claimset_id: "eu.tax.v1",
            registry: eu_tax_v1,
            claim_path: "/claims/tax_residence_country",
            mode: DisclosureMode::Reveal,
        },
        RegistryPolicyCase {
            claimset_id: "eu.passport.v1",
            registry: eu_passport_v1,
            claim_path: "/claims/family_name",
            mode: DisclosureMode::Reveal,
        },
        RegistryPolicyCase {
            claimset_id: "eu.driving_license.v1",
            registry: eu_driving_license_v1,
            claim_path: "/claims/family_name",
            mode: DisclosureMode::Reveal,
        },
        RegistryPolicyCase {
            claimset_id: "eu.diploma.v1",
            registry: eu_diploma_v1,
            claim_path: "/claims/credential_title",
            mode: DisclosureMode::Reveal,
        },
        RegistryPolicyCase {
            claimset_id: "eu.health.v1",
            registry: eu_health_v1,
            claim_path: "/claims/family_name",
            mode: DisclosureMode::Reveal,
        },
        RegistryPolicyCase {
            claimset_id: "eu.professional_license.v1",
            registry: eu_professional_license_v1,
            claim_path: "/claims/profession",
            mode: DisclosureMode::Reveal,
        },
        RegistryPolicyCase {
            claimset_id: "eu.eidas-vid.v1",
            registry: eu_eidas_vid_v1,
            claim_path: "/claims/family_name",
            mode: DisclosureMode::Reveal,
        },
    ];

    for case in cases {
        let policy = policy_for_claimset(case.claimset_id)
            .unwrap()
            .require_claim(case.claim_path, case.mode);

        assert!(
            validate_policy_claims_against_registry(&policy, &(case.registry)()).is_ok(),
            "policy profile {} rejected representative claim {}",
            case.claimset_id,
            case.claim_path,
        );
    }
}

#[test]
fn policy_fails_closed_when_derivation_is_disallowed() {
    let policy = policy_for_claimset("eu.tax.v1")
        .unwrap()
        .require_claim("/claims/tax_identifier", DisclosureMode::Hidden);

    let err = plan_satisfaction(&policy).unwrap_err();

    assert_eq!(err, VpPolicyError::ZkDerivationUnavailable);
}

#[test]
fn policy_defers_derivation_capability_to_the_protocol_layer() {
    let policy = policy_for_claimset("eu.age.v1")
        .unwrap()
        .require_claim("/claims/age", DisclosureMode::MemberOfSet);

    let plan = plan_satisfaction(&policy).unwrap();

    match plan {
        SatisfactionPlan::Derive(plan) => {
            assert_eq!(plan.inputs.len(), 1);
            assert_eq!(plan.inputs[0].claim_path, "/claims/age");
            assert_eq!(plan.inputs[0].mode, DisclosureMode::MemberOfSet);
        }
        SatisfactionPlan::Disclose(_) => panic!("predicate must require derivation"),
    }
}
