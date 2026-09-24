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
//! Tests for built-in VP policy profiles.

use identity_presentation_vp_policy::{
    evaluate, profiles::eu_pid_policy, EvaluationContext, PolicyDecision, StatusContext,
};

use identity_core_primitives::Algorithm;
use identity_credential_claims_core::ClaimsRegistry;
use identity_presentation_vp_core::model::{Presentation, SdJwtVcPresentation};
use reallyme_credential_audit::{IdentityProofingLevel, QeaaCompliance};

use identity_credential_status_core::{
    CredentialStatusError, StatusList, StatusListAlgorithm, StatusListSignature,
    StatusListVerifier, StatusPurpose,
};

use std::collections::BTreeMap;

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

fn empty_registry(claimset_id: &str) -> ClaimsRegistry {
    ClaimsRegistry {
        claimset_id: claimset_id.into(),
        claims: BTreeMap::new(),
    }
}

fn dummy_presentation() -> Presentation {
    Presentation::SdJwtVc(Box::new(SdJwtVcPresentation {
        sd_jwt: "dummy".into(),
        disclosures: vec![],
        kb_jwt: None,
        vct: None,
        envelope_hash: None,
    }))
}

// -----------------------------------------------------------------------------
// QEAA fixtures
// -----------------------------------------------------------------------------

fn valid_qeaa() -> QeaaCompliance {
    QeaaCompliance {
        qtsp: reallyme_credential_audit::QtspInfo {
            tsp_name: "QTSP".into(),
            tsp_id: "QTSP-1".into(),
            tsp_role: reallyme_credential_audit::QtspRole::QeaaProvider,
        },
        policies: reallyme_credential_audit::QeaaPolicies {
            policy_id: "QEAA-ETSI-1.0".into(),
            standards: vec!["ETSI".into()],
        },
        issuer_credential: reallyme_credential_audit::IssuerCredential {
            kind: reallyme_credential_audit::IssuerCredentialKind::X509,
            cert_fingerprint_sha256: [0u8; 32],
            cert_chain_der: vec![vec![1, 2, 3]],
            trusted_list_ref: "EU-TL".into(),
            policy_oids: vec![],
            qcstatements_oids: vec![],
        },
        key_management: reallyme_credential_audit::KeyManagement {
            signing_key_id: "key".into(),
            protection: reallyme_credential_audit::KeyProtection::Hsm,
        },
        identity_proofing: reallyme_credential_audit::IdentityProofing {
            standard: "ETSI TS 119 461".into(),
            loip: IdentityProofingLevel::High,
            evidence_ref: "evidence".into(),
            evidence_hash: [1u8; 32],
        },
        audit: reallyme_credential_audit::AuditInfo {
            audit_standard: "ETSI".into(),
            audit_report_ref: "report".into(),
            audit_report_hash: [2u8; 32],
            period_from_unix: 1_700_000_000,
            period_to_unix: 1_750_000_000,
        },
        revocation: reallyme_credential_audit::RevocationPolicy {
            status_method: reallyme_credential_audit::StatusMethod::StatusList,
            signing_key_id: "status-key".into(),
            max_status_age_seconds: 3600,
        },
    }
}

// -----------------------------------------------------------------------------
// Status fixtures
// -----------------------------------------------------------------------------

struct AcceptAllStatusVerifier;

impl StatusListVerifier for AcceptAllStatusVerifier {
    fn verify_status_list(
        &self,
        _issuer_did: &str,
        _alg: StatusListAlgorithm,
        _message: &[u8],
        _sig: &[u8],
    ) -> Result<(), CredentialStatusError> {
        Ok(())
    }
}

// -----------------------------------------------------------------------------
// Profile tests
// -----------------------------------------------------------------------------

#[test]
fn pid_profile_requires_qeaa() {
    let policy = eu_pid_policy();

    let decision = evaluate(
        &policy,
        &EvaluationContext {
            binding_ok: true,
            now_unix: 1_700_000_000,
            presentation: &dummy_presentation(),
            issuer_algorithm: Algorithm::Ed25519,
            holder_algorithm: Algorithm::Ed25519,
            claims_registry: &empty_registry("eu.pid.v1"),
            claimset_id: "eu.pid.v1",
            status: None,
            qeaa: None,
            qeaa_audit_ok: None,
        },
    );

    assert!(matches!(decision, PolicyDecision::Reject(_)));
}

#[test]
fn pid_profile_accepts_valid_qeaa() {
    let policy = eu_pid_policy();
    let qeaa = valid_qeaa();

    let status_list = StatusList {
        issuer: "did:test:issuer".into(),
        purpose: StatusPurpose::Revocation,
        issued_at: 1_700_000_000,
        next_update: 1_800_000_000,
        encoded_list: vec![0u8],
        length: 1,
        list_id: None,
        signature: StatusListSignature {
            alg: StatusListAlgorithm::Ed25519,
            sig_bytes: vec![1, 2, 3],
        },
    };

    let verifier = AcceptAllStatusVerifier;

    let decision = evaluate(
        &policy,
        &EvaluationContext {
            binding_ok: true,
            now_unix: 1_700_000_000,
            presentation: &dummy_presentation(),
            issuer_algorithm: Algorithm::Ed25519,
            holder_algorithm: Algorithm::Ed25519,
            claims_registry: &empty_registry("eu.pid.v1"),
            claimset_id: "eu.pid.v1",
            status: Some(StatusContext {
                list: &status_list,
                index: 0,
                verifier: &verifier,
            }),
            qeaa: Some(&qeaa),
            qeaa_audit_ok: Some(&qeaa),
        },
    );

    assert_eq!(decision, PolicyDecision::Accept);
}
#[test]
fn pid_profile_rejects_low_loip() {
    let mut qeaa = valid_qeaa();
    qeaa.identity_proofing.loip = IdentityProofingLevel::Baseline;

    let policy = eu_pid_policy();

    // --- status list lives in this scope ---
    let status_list = StatusList {
        issuer: "did:test:issuer".into(),
        purpose: StatusPurpose::Revocation,
        issued_at: 1_700_000_000,
        next_update: 1_800_000_000,
        encoded_list: vec![0u8], // bit 0 = active
        length: 1,
        list_id: None,
        signature: StatusListSignature {
            alg: StatusListAlgorithm::Ed25519,
            sig_bytes: vec![1, 2, 3],
        },
    };

    let verifier = AcceptAllStatusVerifier;

    let decision = evaluate(
        &policy,
        &EvaluationContext {
            binding_ok: true,
            now_unix: 1_700_000_000,
            presentation: &dummy_presentation(),
            issuer_algorithm: Algorithm::Ed25519,
            holder_algorithm: Algorithm::Ed25519,
            claims_registry: &empty_registry("eu.pid.v1"),
            claimset_id: "eu.pid.v1",
            status: Some(StatusContext {
                list: &status_list,
                index: 0,
                verifier: &verifier,
            }),
            qeaa: Some(&qeaa),
            qeaa_audit_ok: Some(&qeaa),
        },
    );

    assert!(matches!(decision, PolicyDecision::Reject(_)));
}
