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
    validate_presentation, CryptoContext, QeaaContext, VpValidationError, VpValidationInput,
};

use identity_core_primitives::Algorithm;
use identity_credential_claims_core::ClaimsRegistry;
use identity_presentation_vp_core::model::{Presentation, SdJwtVcPresentation};

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
    Presentation::SdJwtVc(Box::new(SdJwtVcPresentation {
        sd_jwt: "dummy.jwt".into(),
        disclosures: vec![],
        kb_jwt: None,
        vct: None,
        envelope_hash: None,
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
            cert_fingerprint_sha256: [3u8; 32],
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

    let status_ctx = StatusContext {
        list: &status_list,
        index: 0,
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
