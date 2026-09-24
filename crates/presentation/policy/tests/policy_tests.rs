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
//! Tests for core VP policy evaluation.

use identity_core_primitives::Algorithm;
use identity_credential_claims_core::ClaimsRegistry;
use identity_presentation_vp_core::model::{Presentation, SdJwtVcPresentation};
use identity_presentation_vp_policy::{evaluate, EvaluationContext, PolicyDecision, VpPolicy};

#[test]
fn accepts_valid_sd_jwt_with_required_claim() {
    let registry = ClaimsRegistry {
        claimset_id: "test".into(),
        claims: std::collections::BTreeMap::new(),
    };

    let policy = VpPolicy {
        allowed_issuer_algorithms: vec![Algorithm::Ed25519],
        allowed_holder_algorithms: vec![Algorithm::Ed25519],

        allow_sd_jwt: true,
        allow_zk: false,

        required_claims: vec![],
        allowed_claimsets: None,

        require_status: false,
        max_status_age_seconds: None,

        require_qeaa: false,
        min_qeaa_profile: None,
        min_identity_proofing_level: None,
    };

    let presentation = Presentation::SdJwtVc(Box::new(SdJwtVcPresentation {
        sd_jwt: "dummy".into(),
        disclosures: vec![],
        kb_jwt: None,
        vct: None,
        envelope_hash: None,
    }));

    let decision = evaluate(
        &policy,
        &EvaluationContext {
            binding_ok: true,
            now_unix: 1_700_000_000,
            presentation: &presentation,
            issuer_algorithm: Algorithm::Ed25519,
            holder_algorithm: Algorithm::Ed25519,
            claims_registry: &registry,
            claimset_id: "test",
            status: None,
            qeaa: None,
            qeaa_audit_ok: None,
        },
    );

    assert_eq!(decision, PolicyDecision::Accept);
}
