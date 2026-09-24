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
//! Tests for QEAA-aware VP policy decisions.

use identity_core_primitives::Algorithm;
use identity_credential_claims_core::ClaimsRegistry;
use identity_presentation_vp_core::model::{Presentation, SdJwtVcPresentation};
use identity_presentation_vp_policy::{
    evaluate, EvaluationContext, PolicyDecision, VpPolicy, VpPolicyError,
};

use reallyme_credential_audit::{
    AuditInfo, IdentityProofing, IdentityProofingLevel, IssuerCredential, KeyManagement,
    QeaaCompliance, QeaaPolicies, QtspInfo, RevocationPolicy, StatusMethod,
};
use std::collections::BTreeMap;

fn sample_qeaa() -> QeaaCompliance {
    QeaaCompliance {
        qtsp: QtspInfo {
            tsp_name: "Test QTSP".into(),
            tsp_id: "QTSP-123".into(),
            tsp_role: reallyme_credential_audit::QtspRole::QeaaProvider,
        },
        policies: QeaaPolicies {
            policy_id: "QEAA-ETSI-1.0".into(),
            standards: vec!["ETSI TS 119 461".into()],
        },
        issuer_credential: IssuerCredential {
            kind: reallyme_credential_audit::IssuerCredentialKind::X509,
            cert_fingerprint_sha256: [0u8; 32],
            cert_chain_der: vec![vec![1, 2, 3]],
            trusted_list_ref: "EU-TL".into(),
            policy_oids: vec![],
            qcstatements_oids: vec![],
        },
        key_management: KeyManagement {
            signing_key_id: "key-1".into(),
            protection: reallyme_credential_audit::KeyProtection::Hsm,
        },
        identity_proofing: IdentityProofing {
            standard: "ETSI TS 119 461".into(),
            loip: IdentityProofingLevel::High,
            evidence_ref: "evidence://ref".into(),
            evidence_hash: [1u8; 32],
        },
        audit: AuditInfo {
            audit_standard: "ETSI".into(),
            audit_report_ref: "report://ref".into(),
            audit_report_hash: [2u8; 32],
            period_from_unix: 1_700_000_000,
            period_to_unix: 1_750_000_000,
        },
        revocation: RevocationPolicy {
            status_method: StatusMethod::StatusList,
            signing_key_id: "status-key".into(),
            max_status_age_seconds: 3600,
        },
    }
}

#[test]
fn qeaa_required_policy_rejects_missing_qeaa() {
    let registry = ClaimsRegistry {
        claimset_id: "eu.pid.v1".into(),
        claims: BTreeMap::new(),
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
        require_qeaa: true,
        min_qeaa_profile: Some("QEAA-ETSI-1.0".into()),
        min_identity_proofing_level: Some(3), // HIGH
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
            now_unix: 1_720_000_000,
            presentation: &presentation,
            issuer_algorithm: Algorithm::Ed25519,
            holder_algorithm: Algorithm::Ed25519,
            claims_registry: &registry,
            claimset_id: "eu.pid.v1",
            status: None,
            qeaa: None,
            qeaa_audit_ok: None, // ❌ missing audit
        },
    );

    assert!(matches!(
        decision,
        PolicyDecision::Reject(errs)
        if errs.contains(&VpPolicyError::QeaaRequired)
    ));
}

#[test]
fn qeaa_required_policy_accepts_valid_qeaa() {
    let registry = ClaimsRegistry {
        claimset_id: "eu.pid.v1".into(),
        claims: BTreeMap::new(),
    };

    let qeaa = sample_qeaa();

    let policy = VpPolicy {
        allowed_issuer_algorithms: vec![Algorithm::Ed25519],
        allowed_holder_algorithms: vec![Algorithm::Ed25519],
        allow_sd_jwt: true,
        allow_zk: false,
        required_claims: vec![],
        allowed_claimsets: None,
        require_status: false,
        max_status_age_seconds: None,
        require_qeaa: true,
        min_qeaa_profile: Some("QEAA-ETSI-1.0".into()),
        min_identity_proofing_level: Some(3),
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
            now_unix: 1_720_000_000,
            presentation: &presentation,
            issuer_algorithm: Algorithm::Ed25519,
            holder_algorithm: Algorithm::Ed25519,
            claims_registry: &registry,
            claimset_id: "eu.pid.v1",
            status: None,
            qeaa: Some(&qeaa),
            qeaa_audit_ok: Some(&qeaa), // ✅ validated QEAA
        },
    );

    assert_eq!(decision, PolicyDecision::Accept);
}
