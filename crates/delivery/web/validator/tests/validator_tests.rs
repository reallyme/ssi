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
//! Tests for web delivery presentation validation.

use identity_credential_claims_core::ClaimsRegistry;
use identity_credential_status_core::{
    CredentialStatusError, StatusList, StatusListAlgorithm, StatusListSignature,
    StatusListVerifier, StatusPurpose,
};
use identity_presentation_delivery_web_validator::{
    validate_web_presentation, WebValidationInput, WebValidationResult,
};
use identity_presentation_vp_core::model::{
    CredentialReference, CredentialStatusRef, Presentation, PresentationFreshness,
    SdJwtVcPresentation, StatusPurpose as VpStatusPurpose, ZkPresentation, ZkProof,
};
use identity_presentation_vp_policy::StatusContext;
use identity_presentation_vp_sd_jwt::ExpectedKbJwtBinding;
use identity_presentation_vp_validator::{QeaaContext, VpValidationError};
use reallyme_credential_audit::{IdentityProofingLevel, QeaaCompliance};

use crypto_core::Algorithm;
use crypto_dispatch::generate_keypair;
use envelopes_jwk::{Jwk, OkpJwk};
use envelopes_jwt::jwt::{
    encode_signed_jwt, encode_signed_jwt_with_header_options, JwtHeaderEncodeOptions,
};
use reallyme_credential::committed::model::{
    AssuranceLevel, ClaimsCommitment, CommitmentLimits, CredentialAlgorithm, CredentialEnvelope,
    CredentialKind, CredentialStatus, CredentialSubject, DomainTags, HolderBinding, KeyAssurance,
    KeyReference, PartyReference, PublicKeyRef, PublicKeyRepresentation, RawPublicKeySerialization,
    Signature as VcSignature,
};
use reallyme_crypto::sha2::digest as sha2_256_digest;

use std::collections::BTreeMap;

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

fn empty_registry(id: &str) -> ClaimsRegistry {
    ClaimsRegistry {
        claimset_id: id.into(),
        claims: BTreeMap::new(),
    }
}

fn dummy_presentation() -> Presentation {
    let sd_jwt = concat!(
        "eyJhbGciOiJFZERTQSJ9.", // {"alg":"EdDSA"}
        "e30.",                  // {}
        "sig"
    );

    Presentation::SdJwtVc(Box::new(SdJwtVcPresentation {
        sd_jwt: sd_jwt.into(),
        disclosures: vec![],
        kb_jwt: None,
        vct: None,
        envelope_hash: None,
    }))
}

fn ed25519_key(did_url: &str, bytes: Vec<u8>) -> PublicKeyRef {
    PublicKeyRef {
        alg: CredentialAlgorithm::Ed25519,
        reference: KeyReference::DidVerificationMethod(did_url.into()),
        public_key: PublicKeyRepresentation::Raw {
            serialization: RawPublicKeySerialization::FixedWidth,
            bytes,
        },
        assurance: KeyAssurance::None,
    }
}

fn real_sd_jwt_presentation_and_crypto_inputs(
    now_unix: u64,
) -> (Presentation, CredentialEnvelope, Vec<u8>) {
    let (issuer_pub, issuer_priv) = generate_keypair(Algorithm::Ed25519).unwrap();
    let issuer_jwk = Jwk::Okp(OkpJwk {
        kty: "OKP".into(),
        crv: "Ed25519".into(),
        x: codec_base64url::bytes_to_base64url(&issuer_pub),
        alg: Some("EdDSA".into()),
        kid: None,
        use_: Some("sig".into()),
    });

    let (holder_pub, holder_priv) = generate_keypair(Algorithm::Ed25519).unwrap();
    let holder_jwk = Jwk::Okp(OkpJwk {
        kty: "OKP".into(),
        crv: "Ed25519".into(),
        x: codec_base64url::bytes_to_base64url(&holder_pub),
        alg: Some("EdDSA".into()),
        kid: None,
        use_: Some("sig".into()),
    });

    let sd_hash = [7u8; 32];
    let sd_payload = serde_json::json!({
        "nbf": 1,
        "exp": 9_999_999_999u64,
        "sd_hash": codec_base64url::bytes_to_base64url(sd_hash.as_slice()),
    });
    let sd_jwt = encode_signed_jwt(&sd_payload, &issuer_jwk, &issuer_priv).unwrap();
    let kb_payload = serde_json::json!({
        "sd_hash": codec_base64url::bytes_to_base64url(sd_hash.as_slice()),
        "aud": "verifier.example",
        "nonce": "nonce-123",
        "iat": now_unix,
        "exp": now_unix + 300,
        "cnf": { "jwk": holder_jwk },
    });
    let kb_jwt = encode_signed_jwt_with_header_options(
        &kb_payload,
        &holder_jwk,
        &holder_priv,
        &JwtHeaderEncodeOptions::new(Some("kb+jwt".to_owned())),
    )
    .unwrap();

    let status_list_encoded = vec![0u8];
    let status_list_id = sha2_256_digest(&status_list_encoded).into_bytes();

    let env = CredentialEnvelope {
        kind: CredentialKind::Pid,
        profile_id: "eu.pid.v1".into(),
        assurance: AssuranceLevel::High,
        issuer_reference: PartyReference::Did("did:test:issuer".into()),
        issuer_country: "EU".into(),
        valid_from: now_unix as i64 - 60,
        valid_until: now_unix as i64 + 3600,
        status: CredentialStatus {
            status_list_url: "https://example.com/status".into(),
            status_list_id,
            status_list_index: 0,
            purpose: reallyme_credential::committed::model::StatusPurpose::Revocation,
        },
        subject: CredentialSubject {
            subject_reference: PartyReference::OpaqueIdentifier("subject".into()),
            holder_binding: HolderBinding::CryptographicKey(ed25519_key(
                "did:test:subject#key-1",
                holder_pub,
            )),
        },
        claims_commitment: ClaimsCommitment {
            merkle_root: vec![9u8; 32],
            claimset_id: "eu.pid.v1".into(),
            hash_alg: "sha-256".into(),
            value_encoding: "RM-CV-JCS-V1".into(),
            domain_tags: DomainTags {
                clm: "clm".into(),
                leaf: "leaf".into(),
                node: "node".into(),
            },
            limits: CommitmentLimits {
                max_value_len: 2048,
                salt_len: 16,
            },
        },
        qeaa_compliance: None,
        issuer_signature: VcSignature {
            verification_key: ed25519_key("did:test:issuer#key-1", issuer_pub.clone()),
            raw_rs: vec![0u8; 64],
        },
    };

    (
        Presentation::SdJwtVc(Box::new(SdJwtVcPresentation {
            sd_jwt,
            disclosures: vec![],
            kb_jwt: Some(kb_jwt),
            vct: None,
            envelope_hash: Some(sd_hash),
        })),
        env,
        issuer_pub,
    )
}

fn expected_sd_jwt_binding(now_unix: u64) -> ExpectedKbJwtBinding<'static> {
    ExpectedKbJwtBinding {
        expected_audience: "verifier.example",
        expected_nonce_32: sha2_256_digest(b"nonce-123").into_bytes(),
        now_unix,
        max_iat_age_seconds: 300,
        max_future_iat_skew_seconds: 60,
    }
}

fn dummy_zk_presentation(circuit_id: &str) -> Presentation {
    let mut public_inputs = BTreeMap::new();
    public_inputs.insert("envelope_hash".into(), vec![0u8; 32]);
    public_inputs.insert("audience_hash".into(), vec![1u8; 32]);
    public_inputs.insert("challenge".into(), vec![2u8; 32]);
    public_inputs.insert(
        "expiry_unix".into(),
        1_700_000_000u64.to_be_bytes().to_vec(),
    );

    Presentation::Zk(Box::new(ZkPresentation {
        freshness: PresentationFreshness {
            challenge: [2u8; 32],
            audience_hash: [1u8; 32],
            expiry_unix: 1_700_000_000,
        },
        credential: CredentialReference {
            envelope_hash: [0u8; 32],
            issuer_did: "did:test:issuer".into(),
            status: CredentialStatusRef {
                status_list_url: "https://example.com/status".into(),
                status_list_id: [0u8; 32],
                status_list_index: 0,
                purpose: VpStatusPurpose::Revocation,
            },
        },
        disclosures: vec![],
        zk_proof: ZkProof {
            circuit_id: circuit_id.into(),
            circuit_version: "1.0.0".into(),
            vk_id: "vk".into(),
            proof_bytes: vec![1],
            public_inputs,
            proof_suite: identity_presentation_vp_core::model::ZkProofSuite::BarretenbergUltraHonkKeccakZkNoIpa,
            artifact_manifest_sha256: [9_u8; 32],
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
fn web_accepts_valid_pid() {
    let now = 1_720_000_000u64;
    let (pres, envelope, issuer_pk) = real_sd_jwt_presentation_and_crypto_inputs(now);
    let reg = empty_registry("eu.pid.v1");
    let qeaa = valid_qeaa();

    let status_list = StatusList {
        issuer: "did:test:issuer".to_string(),
        purpose: StatusPurpose::Revocation,
        issued_at: 1_700_000_000,
        next_update: 1_800_000_000,
        encoded_list: vec![0],
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

    let result = validate_web_presentation(WebValidationInput {
        presentation: &pres,
        claims_registry: &reg,
        claimset_id: "eu.pid.v1",
        status: Some(status_ctx),
        qeaa: QeaaContext {
            qeaa_from_vc: Some(&qeaa),
        },
        credential_envelope: Some(&envelope),
        sd_jwt_issuer_public_key: Some(issuer_pk.as_slice()),
        sd_jwt_binding: Some(expected_sd_jwt_binding(now)),
        now_unix: now,
    })
    .unwrap();

    assert!(matches!(result, WebValidationResult::Accepted));
}

#[test]
fn web_rejects_holder_bound_sd_jwt_without_relying_party_binding() {
    let now = 1_720_000_000u64;
    let (presentation, envelope, issuer_public_key) =
        real_sd_jwt_presentation_and_crypto_inputs(now);
    let registry = empty_registry("eu.pid.v1");

    let error = validate_web_presentation(WebValidationInput {
        presentation: &presentation,
        claims_registry: &registry,
        claimset_id: "eu.pid.v1",
        status: None,
        qeaa: QeaaContext { qeaa_from_vc: None },
        credential_envelope: Some(&envelope),
        sd_jwt_issuer_public_key: Some(issuer_public_key.as_slice()),
        sd_jwt_binding: None,
        now_unix: now,
    })
    .unwrap_err();

    assert!(matches!(
        error,
        VpValidationError::PolicyRejected(errors)
            if errors.iter().any(|item| matches!(item, identity_presentation_vp_policy::VpPolicyError::ProofInvalid))
    ));
}

#[test]
fn web_rejects_holder_binding_for_a_different_audience() {
    let now = 1_720_000_000u64;
    let (presentation, envelope, issuer_public_key) =
        real_sd_jwt_presentation_and_crypto_inputs(now);
    let registry = empty_registry("eu.pid.v1");
    let mut binding = expected_sd_jwt_binding(now);
    binding.expected_audience = "other-verifier.example";

    let error = validate_web_presentation(WebValidationInput {
        presentation: &presentation,
        claims_registry: &registry,
        claimset_id: "eu.pid.v1",
        status: None,
        qeaa: QeaaContext { qeaa_from_vc: None },
        credential_envelope: Some(&envelope),
        sd_jwt_issuer_public_key: Some(issuer_public_key.as_slice()),
        sd_jwt_binding: Some(binding),
        now_unix: now,
    })
    .unwrap_err();

    assert!(matches!(
        error,
        VpValidationError::PolicyRejected(errors)
            if errors.iter().any(|item| matches!(item, identity_presentation_vp_policy::VpPolicyError::ProofInvalid))
    ));
}

#[test]
fn web_rejects_missing_qeaa() {
    let now = 1_720_000_000u64;
    let (pres, envelope, issuer_pk) = real_sd_jwt_presentation_and_crypto_inputs(now);
    let reg = empty_registry("eu.pid.v1");

    let status_list = StatusList {
        issuer: "did:test:issuer".to_string(),
        purpose: StatusPurpose::Revocation,
        issued_at: 1_700_000_000,
        next_update: 1_800_000_000,
        encoded_list: vec![0],
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

    let err = validate_web_presentation(WebValidationInput {
        presentation: &pres,
        claims_registry: &reg,
        claimset_id: "eu.pid.v1",
        status: Some(status_ctx),
        qeaa: QeaaContext { qeaa_from_vc: None },
        credential_envelope: Some(&envelope),
        sd_jwt_issuer_public_key: Some(issuer_pk.as_slice()),
        sd_jwt_binding: Some(expected_sd_jwt_binding(now)),
        now_unix: now,
    })
    .unwrap_err();

    assert!(matches!(
        err,
        VpValidationError::PolicyRejected(errs)
            if errs.iter().any(|e| matches!(e, identity_presentation_vp_policy::VpPolicyError::QeaaRequired))
    ));
}

#[test]
fn web_rejects_unknown_claimset() {
    let now = 1_720_000_000u64;
    let (pres, envelope, issuer_pk) = real_sd_jwt_presentation_and_crypto_inputs(now);
    let reg = empty_registry("unknown.claimset");

    let err = validate_web_presentation(WebValidationInput {
        presentation: &pres,
        claims_registry: &reg,
        claimset_id: "unknown.claimset",
        status: None,
        qeaa: QeaaContext { qeaa_from_vc: None },
        credential_envelope: Some(&envelope),
        sd_jwt_issuer_public_key: Some(issuer_pk.as_slice()),
        sd_jwt_binding: Some(expected_sd_jwt_binding(now)),
        now_unix: now,
    })
    .unwrap_err();

    assert!(matches!(err, VpValidationError::UnsupportedClaimset));
}

#[test]
fn web_rejects_dummy_sd_jwt_presentation_crypto_failure() {
    let now = 1_720_000_000u64;
    let (_real_pres, envelope, issuer_pk) = real_sd_jwt_presentation_and_crypto_inputs(now);
    let reg = empty_registry("eu.pid.v1");

    let err = validate_web_presentation(WebValidationInput {
        presentation: &dummy_presentation(),
        claims_registry: &reg,
        claimset_id: "eu.pid.v1",
        status: None,
        qeaa: QeaaContext { qeaa_from_vc: None },
        credential_envelope: Some(&envelope),
        sd_jwt_issuer_public_key: Some(issuer_pk.as_slice()),
        sd_jwt_binding: Some(expected_sd_jwt_binding(now)),
        now_unix: now,
    })
    .unwrap_err();

    assert!(matches!(
        err,
        VpValidationError::PolicyRejected(errs)
            if errs.iter().any(|e| matches!(e, identity_presentation_vp_policy::VpPolicyError::ProofInvalid))
    ));
}

#[test]
fn web_rejects_dummy_zk_presentation_crypto_failure() {
    let now = 1_720_000_000u64;
    let reg = empty_registry("eu.age.v1");

    let err = validate_web_presentation(WebValidationInput {
        presentation: &dummy_zk_presentation("rm-zk-vc-base-v1"),
        claims_registry: &reg,
        claimset_id: "eu.age.v1",
        status: None,
        qeaa: QeaaContext { qeaa_from_vc: None },
        credential_envelope: None,
        sd_jwt_issuer_public_key: None,
        sd_jwt_binding: None,
        now_unix: now,
    })
    .unwrap_err();

    assert!(matches!(
        err,
        VpValidationError::PolicyRejected(errs)
            if errs.iter().any(|e| matches!(e, identity_presentation_vp_policy::VpPolicyError::PresentationFormatNotAllowed))
    ));
}
