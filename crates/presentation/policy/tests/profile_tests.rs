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
    evaluate, policy_for_claimset, profiles::eu_pid_policy, EvaluationContext, PolicyDecision,
    StatusContext, VpPolicyError,
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

fn status_list_issued_at(issued_at: u64) -> StatusList {
    StatusList {
        issuer: "did:test:issuer".into(),
        purpose: StatusPurpose::Revocation,
        issued_at,
        next_update: 1_800_000_000,
        encoded_list: vec![0u8],
        length: 1,
        list_id: None,
        signature: StatusListSignature {
            alg: StatusListAlgorithm::Ed25519,
            sig_bytes: vec![1, 2, 3],
        },
    }
}

fn evaluate_pid_at(
    policy: &identity_presentation_vp_policy::VpPolicy,
    claimset_id: &str,
    status_list: &StatusList,
    now_unix: u64,
) -> PolicyDecision {
    let qeaa = valid_qeaa();
    let verifier = AcceptAllStatusVerifier;
    let presentation = dummy_presentation();
    let registry = empty_registry(claimset_id);
    evaluate(
        policy,
        &EvaluationContext {
            binding_ok: true,
            now_unix,
            presentation: &presentation,
            issuer_algorithm: Algorithm::Ed25519,
            holder_algorithm: Algorithm::Ed25519,
            claims_registry: &registry,
            claimset_id,
            status: Some(StatusContext {
                list: status_list,
                index: 0,
                verifier: &verifier,
            }),
            qeaa: Some(&qeaa),
            qeaa_audit_ok: Some(&qeaa),
        },
    )
}

#[test]
fn pid_profile_rejects_status_list_older_than_max_age() {
    let policy = eu_pid_policy();
    let now = 1_700_100_000;

    // 86_400 seconds is the PID profile bound; one second over is stale.
    let stale = status_list_issued_at(now - 86_401);
    assert_eq!(
        evaluate_pid_at(&policy, "eu.pid.v1", &stale, now),
        PolicyDecision::Reject(vec![VpPolicyError::StatusTooOld])
    );

    let boundary = status_list_issued_at(now - 86_400);
    assert_eq!(
        evaluate_pid_at(&policy, "eu.pid.v1", &boundary, now),
        PolicyDecision::Accept
    );
}

#[test]
fn builtin_profiles_reject_foreign_claimset() {
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
        let policy = policy_for_claimset(id).unwrap();
        assert_eq!(policy.allowed_claimsets, Some(vec![id.to_owned()]), "{id}");
    }

    let status = status_list_issued_at(1_700_000_000);
    assert_eq!(
        evaluate_pid_at(&eu_pid_policy(), "eu.age.v1", &status, 1_700_000_000),
        PolicyDecision::Reject(vec![VpPolicyError::ClaimsetNotAllowed])
    );
}

#[test]
fn evaluation_rejects_disclosure_sets_over_the_policy_cap() {
    let policy = eu_pid_policy().require_claim(
        "/claims/age",
        identity_credential_claims_core::DisclosureMode::Reveal,
    );
    let disclosure = codec_base64url::bytes_to_base64url(br#"["c2FsdA","/claims/age","NDI",0,[]]"#);
    let presentation = Presentation::SdJwtVc(Box::new(SdJwtVcPresentation {
        sd_jwt: "dummy".into(),
        disclosures: vec![disclosure; identity_presentation_vp_policy::MAX_POLICY_DISCLOSURES + 1],
        kb_jwt: None,
        vct: None,
        envelope_hash: None,
    }));
    let registry = empty_registry("eu.pid.v1");
    let qeaa = valid_qeaa();
    let status_list = status_list_issued_at(1_700_000_000);
    let verifier = AcceptAllStatusVerifier;

    let decision = evaluate(
        &policy,
        &EvaluationContext {
            binding_ok: true,
            now_unix: 1_700_000_000,
            presentation: &presentation,
            issuer_algorithm: Algorithm::Ed25519,
            holder_algorithm: Algorithm::Ed25519,
            claims_registry: &registry,
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

    match decision {
        PolicyDecision::Reject(errors) => {
            assert!(errors.contains(&VpPolicyError::ProofInvalid));
        }
        PolicyDecision::Accept => panic!("oversized disclosure set must be rejected"),
    }
}
