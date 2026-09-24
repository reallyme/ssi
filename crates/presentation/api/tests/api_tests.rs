// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! VP API integration tests.

use identity_core_primitives::Algorithm;
use reallyme_disclosure_policy::{
    eu_pid_policy, EvaluationContext, ExtractedDisclosure, QeaaContext, StatusContext,
    VpPolicyError,
};
use reallyme_vp_api::{
    classify_failures, validate_vp, validate_vp_strict, VpApiError, VpFailureClass,
    VpVerificationOutcome,
};
use reallyme_vp_core::{DisclosureMode, Presentation, SdJwtVcPresentation};

fn presentation() -> Presentation {
    Presentation::SdJwtVc(Box::new(SdJwtVcPresentation {
        sd_jwt: "header.payload.signature".to_owned(),
        disclosures: vec!["disclosure".to_owned()],
        kb_jwt: Some("kb.header.payload.signature".to_owned()),
        vct: Some("eu.pid.v1".to_owned()),
        envelope_hash: Some([3u8; 32]),
    }))
}

#[test]
fn validate_vp_returns_truth_first_acceptance_report() {
    let presentation = presentation();
    let policy = eu_pid_policy().require_claim("/given_name", DisclosureMode::Reveal);
    let disclosures = [ExtractedDisclosure {
        claim_path: "/given_name".to_owned(),
        mode: DisclosureMode::Reveal,
    }];
    let status = StatusContext {
        checked: true,
        revoked: false,
        suspended: false,
        age_seconds: Some(60),
    };
    let qeaa = QeaaContext {
        verified: true,
        profile: Some("QEAA-ETSI-1.0"),
        identity_proofing_rank: Some(3),
    };
    let ctx = EvaluationContext {
        binding_ok: true,
        now_unix: 1_700_000_000,
        presentation: &presentation,
        issuer_algorithm: Algorithm::P256,
        holder_algorithm: Algorithm::P256,
        claimset_id: "eu.pid.v1",
        disclosures: &disclosures,
        status: Some(status),
        qeaa: Some(qeaa),
    };

    let report = validate_vp(&policy, &ctx);

    assert_eq!(report.outcome, VpVerificationOutcome::Accepted);
    assert!(report.errors.is_empty());
    assert!(validate_vp_strict(&policy, &ctx).is_ok());
}

#[test]
fn validate_vp_preserves_all_policy_rejection_classes() {
    let presentation = presentation();
    let mut policy = eu_pid_policy().require_claim("/given_name", DisclosureMode::Reveal);
    policy.allowed_issuer_algorithms = vec![Algorithm::P256];
    policy.allowed_holder_algorithms = vec![Algorithm::P256];
    policy.allowed_claimsets = Some(vec!["eu.pid.v1".to_owned()]);
    let disclosures = [ExtractedDisclosure {
        claim_path: "/given_name".to_owned(),
        mode: DisclosureMode::Hidden,
    }];
    let ctx = EvaluationContext {
        binding_ok: false,
        now_unix: 1_700_000_000,
        presentation: &presentation,
        issuer_algorithm: Algorithm::Ed25519,
        holder_algorithm: Algorithm::Ed25519,
        claimset_id: "eu.eaa.v1",
        disclosures: &disclosures,
        status: None,
        qeaa: None,
    };

    let report = validate_vp(&policy, &ctx);
    let classes = report.failure_classes();

    assert_eq!(report.outcome, VpVerificationOutcome::Rejected);
    assert!(classes.contains(&VpFailureClass::Binding));
    assert!(classes.contains(&VpFailureClass::Algorithm));
    assert!(classes.contains(&VpFailureClass::Claims));
    assert!(classes.contains(&VpFailureClass::Disclosure));
    assert!(classes.contains(&VpFailureClass::Status));
    assert!(classes.contains(&VpFailureClass::Qeaa));

    let strict = validate_vp_strict(&policy, &ctx);

    assert!(matches!(strict, Err(VpApiError::PolicyRejected(_))));
}

#[test]
fn vp_report_classifies_claim_registry_policy_errors_as_claims() {
    let classes = classify_failures(&[
        VpPolicyError::ClaimRegistryInvalid,
        VpPolicyError::RequiredClaimInvalid,
    ]);

    assert_eq!(classes.len(), 1);
    assert!(classes.contains(&VpFailureClass::Claims));
}
