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
//! Tests for the protocol-agnostic VP validator.

use identity_presentation_vp_policy::VpPolicyError;
use identity_presentation_vp_validator::{
    evaluate_presentation_policy as validate_presentation, CryptoContext, QeaaContext,
    VpValidationError, VpValidationInput,
};

use identity_core_primitives::Algorithm;
use identity_credential_claims_core::ClaimsRegistry;
use identity_presentation_vp_core::model::{
    CredentialReference, CredentialStatusRef, Presentation, PresentationFreshness,
    StatusPurpose as PresentationStatusPurpose, ZkPresentation, ZkProof, ZkProofSuite,
};

use reallyme_credential_audit::{IdentityProofingLevel, QeaaCompliance};

use identity_credential_status_core::{
    CredentialStatusError, StatusList, StatusListAlgorithm, StatusListSignature,
    StatusListVerifier, StatusPurpose,
};

use identity_presentation_vp_policy::{PolicyDecision, StatusContext};

use std::collections::BTreeMap;

// -----------------------------------------------------------------------------
// Test helpers
// -----------------------------------------------------------------------------

fn empty_registry(claimset_id: &str) -> ClaimsRegistry {
    ClaimsRegistry {
        claimset_id: claimset_id.into(),
        claims: BTreeMap::new(),
    }
}

fn dummy_presentation() -> Presentation {
    Presentation::Zk(Box::new(ZkPresentation {
        freshness: PresentationFreshness {
            challenge: [1; 32],
            audience_hash: [2; 32],
            expiry_unix: 1_800_000_000,
        },
        credential: CredentialReference {
            envelope_hash: [3; 32],
            issuer_did: "did:test:issuer".to_owned(),
            status: CredentialStatusRef {
                status_list_url: "https://example.test/status".to_owned(),
                status_list_id: [0; 32],
                status_list_index: 0,
                purpose: PresentationStatusPurpose::Revocation,
            },
        },
        disclosures: Vec::new(),
        zk_proof: ZkProof {
            circuit_id: "test-circuit".to_owned(),
            circuit_version: "1".to_owned(),
            vk_id: "test-vk".to_owned(),
            proof_bytes: vec![1],
            public_inputs: BTreeMap::new(),
            proof_suite: ZkProofSuite::BarretenbergUltraHonkKeccakZkNoIpa,
            artifact_manifest_sha256: [4; 32],
        },
        qeaa: None,
    }))
}

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
            cert_fingerprint_sha256: [
                0x03, 0x90, 0x58, 0xc6, 0xf2, 0xc0, 0xcb, 0x49, 0x2c, 0x53, 0x3b, 0x0a, 0x4d, 0x14,
                0xef, 0x77, 0xcc, 0x0f, 0x78, 0xab, 0xcc, 0xce, 0xd5, 0x28, 0x7d, 0x84, 0xa1, 0xa2,
                0x01, 0x1c, 0xfb, 0x81,
            ],
            cert_chain_der: vec![vec![1, 2, 3]],
            trusted_list_ref: "EU-TL".into(),
            policy_oids: vec![],
            qcstatements_oids: vec![],
        },
        key_management: reallyme_credential_audit::KeyManagement {
            signing_key_id: "key-1".into(),
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

// Status verifier that always accepts
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

impl reallyme_credential::CredentialStatusListVerifier for AcceptAllStatusVerifier {
    fn verified_signer(&self) -> reallyme_credential::PartyReference {
        reallyme_credential::PartyReference::Did("did:test:issuer".to_owned())
    }
}

struct RevokedStatusVerifier;

impl StatusListVerifier for RevokedStatusVerifier {
    fn verify_status_list(
        &self,
        _issuer_did: &str,
        _alg: StatusListAlgorithm,
        _message: &[u8],
        _sig: &[u8],
    ) -> Result<(), CredentialStatusError> {
        Err(CredentialStatusError::Revoked)
    }
}

impl reallyme_credential::CredentialStatusListVerifier for RevokedStatusVerifier {
    fn verified_signer(&self) -> reallyme_credential::PartyReference {
        reallyme_credential::PartyReference::Did("did:test:issuer".to_owned())
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn validator_accepts_valid_pid_with_qeaa_and_binding() {
    let pres = dummy_presentation();
    let reg = empty_registry("eu.pid.v1");
    let qeaa = valid_qeaa();

    let status_list = StatusList {
        issuer: "did:test:issuer".into(),
        purpose: StatusPurpose::Revocation,
        // Within the PID profile's 24h status freshness bound at `now_unix`.
        issued_at: 1_719_990_000,
        next_update: 1_800_000_000,
        encoded_list: vec![0u8],
        length: 1,
        list_id: Some([0_u8; 32]),
        signature: StatusListSignature {
            alg: StatusListAlgorithm::Ed25519,
            sig_bytes: vec![1, 2, 3],
        },
    };

    let verifier = AcceptAllStatusVerifier;

    let status_ctx = StatusContext {
        list: &status_list,
        verifier: &verifier,
    };

    let input = VpValidationInput {
        presentation: &pres,
        claims_registry: &reg,
        claimset_id: "eu.pid.v1",
        crypto: CryptoContext {
            issuer_algorithm: Algorithm::Ed25519,
            holder_algorithm: Algorithm::Ed25519,
        },
        status: Some(status_ctx),
        qeaa: QeaaContext {
            qeaa_from_vc: Some(&qeaa),
        },
        binding_ok: true,
        now_unix: 1_720_000_000,
    };

    let decision = validate_presentation(input).unwrap();

    assert!(matches!(decision, PolicyDecision::Accept));
}

#[test]
fn validator_rejects_authenticated_revoked_status() {
    let presentation = dummy_presentation();
    let registry = empty_registry("eu.pid.v1");
    let qeaa = valid_qeaa();
    let status_list = StatusList {
        issuer: "did:test:issuer".into(),
        purpose: StatusPurpose::Revocation,
        issued_at: 1_719_990_000,
        next_update: 1_800_000_000,
        encoded_list: vec![0_u8],
        length: 1,
        list_id: Some([0_u8; 32]),
        signature: StatusListSignature {
            alg: StatusListAlgorithm::Ed25519,
            sig_bytes: vec![1, 2, 3],
        },
    };
    let verifier = RevokedStatusVerifier;

    let error = validate_presentation(VpValidationInput {
        presentation: &presentation,
        claims_registry: &registry,
        claimset_id: "eu.pid.v1",
        crypto: CryptoContext {
            issuer_algorithm: Algorithm::Ed25519,
            holder_algorithm: Algorithm::Ed25519,
        },
        status: Some(StatusContext {
            list: &status_list,
            verifier: &verifier,
        }),
        qeaa: QeaaContext {
            qeaa_from_vc: Some(&qeaa),
        },
        binding_ok: true,
        now_unix: 1_720_000_000,
    })
    .expect_err("revoked status must be terminal at the validator boundary");

    assert!(matches!(
        error,
        VpValidationError::PolicyRejected(errors)
            if errors.contains(&VpPolicyError::CredentialRevoked)
    ));
}

#[test]
fn validator_rejects_pid_without_qeaa() {
    let pres = dummy_presentation();
    let reg = empty_registry("eu.pid.v1");

    let input = VpValidationInput {
        presentation: &pres,
        claims_registry: &reg,
        claimset_id: "eu.pid.v1",
        crypto: CryptoContext {
            issuer_algorithm: Algorithm::Ed25519,
            holder_algorithm: Algorithm::Ed25519,
        },
        status: None,
        qeaa: QeaaContext { qeaa_from_vc: None },
        binding_ok: true,
        now_unix: 1_720_000_000,
    };

    let err = validate_presentation(input).unwrap_err();

    assert!(matches!(
        err,
        VpValidationError::PolicyRejected(errs)
            if errs.iter().any(|e| matches!(e, VpPolicyError::QeaaRequired))
    ));
}

#[test]
fn validator_rejects_low_loip_qeaa() {
    let pres = dummy_presentation();
    let reg = empty_registry("eu.pid.v1");

    let mut qeaa = valid_qeaa();
    qeaa.identity_proofing.loip = IdentityProofingLevel::Baseline;

    let input = VpValidationInput {
        presentation: &pres,
        claims_registry: &reg,
        claimset_id: "eu.pid.v1",
        crypto: CryptoContext {
            issuer_algorithm: Algorithm::Ed25519,
            holder_algorithm: Algorithm::Ed25519,
        },
        status: None,
        qeaa: QeaaContext {
            qeaa_from_vc: Some(&qeaa),
        },
        binding_ok: true,
        now_unix: 1_720_000_000,
    };

    let err = validate_presentation(input).unwrap_err();

    assert!(matches!(
        err,
        VpValidationError::PolicyRejected(errs)
            if errs.iter().any(|e| matches!(e, VpPolicyError::QeaaLevelInsufficient))
    ));
}

#[test]
fn validator_rejects_unknown_claimset() {
    let pres = dummy_presentation();
    let reg = empty_registry("unknown.claimset");

    let input = VpValidationInput {
        presentation: &pres,
        claims_registry: &reg,
        claimset_id: "unknown.claimset",
        crypto: CryptoContext {
            issuer_algorithm: Algorithm::Ed25519,
            holder_algorithm: Algorithm::Ed25519,
        },
        status: None,
        qeaa: QeaaContext { qeaa_from_vc: None },
        binding_ok: true,
        now_unix: 1_720_000_000,
    };

    let err = validate_presentation(input).unwrap_err();
    assert!(matches!(err, VpValidationError::UnsupportedClaimset));
}
