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
use identity_presentation_vp_policy::VpPolicyError;
use identity_presentation_vp_sd_jwt::{
    build_sd_jwt_presentation, build_sd_jwt_presentation_with_kb_binding, ExpectedKbJwtBinding,
    KbJwtBindingInput,
};
use identity_presentation_vp_validator::VpValidationError;
use reallyme_credential_audit::{IdentityProofingLevel, QeaaCompliance};

use crypto_core::Algorithm;
use crypto_dispatch::generate_keypair;
use envelopes_jwk::{Jwk, OkpJwk};
use envelopes_jwt::jwt::encode_signed_jwt;
use reallyme_credential::committed::issue::{issue_credential, IssueInput, OsSaltRng};
use reallyme_credential::committed::model::{
    AssuranceLevel, CommitmentLimits, CredentialAlgorithm, CredentialEnvelope, CredentialKind,
    CredentialStatus, CredentialSubject, DomainTags, HolderBinding, KeyAssurance, KeyReference,
    PartyReference, PublicKeyRef, PublicKeyRepresentation, RawPublicKeySerialization,
};
use reallyme_crypto::sha2::digest as sha2_256_digest;

use std::collections::BTreeMap;
use zeroize::Zeroizing;

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

const STATUS_LIST_ID: [u8; 32] = [0x42; 32];
const ISSUER_DID: &str = "did:test:issuer";

#[derive(Clone, Copy, PartialEq, Eq)]
enum FixtureHolderBinding {
    Key,
    Bearer,
}

struct CredentialFixture {
    presentation: Presentation,
    envelope: CredentialEnvelope,
    issuer_public_key: Vec<u8>,
    issuer_jwk: Jwk,
    issuer_private_key: Zeroizing<Vec<u8>>,
}

fn issue_fixture(
    now_unix: u64,
    with_qeaa: bool,
    holder_binding: FixtureHolderBinding,
    issuer: Option<(Vec<u8>, Zeroizing<Vec<u8>>)>,
) -> CredentialFixture {
    let (issuer_pub, issuer_priv) =
        issuer.unwrap_or_else(|| generate_keypair(Algorithm::Ed25519).unwrap());
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

    let valid_from = i64::try_from(now_unix).unwrap() - 3_600;
    let valid_until = i64::try_from(now_unix).unwrap() + 3_600;
    let input = IssueInput {
        kind: if with_qeaa {
            CredentialKind::Qeaa
        } else {
            CredentialKind::Pid
        },
        profile_id: "eu.pid.v1".into(),
        assurance: AssuranceLevel::High,
        issuer_reference: PartyReference::Did(ISSUER_DID.into()),
        issuer_verification_key: ed25519_key("did:test:issuer#key-1", issuer_pub.clone()),
        issuer_country: "EU".into(),
        valid_from,
        valid_until,
        status: CredentialStatus {
            status_list_url: "https://example.com/status".into(),
            status_list_id: STATUS_LIST_ID,
            status_list_index: 0,
            purpose: reallyme_credential::committed::model::StatusPurpose::Revocation,
        },
        subject: CredentialSubject {
            subject_reference: PartyReference::OpaqueIdentifier("subject".into()),
            holder_binding: match holder_binding {
                FixtureHolderBinding::Key => HolderBinding::CryptographicKey(ed25519_key(
                    "did:test:subject#key-1",
                    holder_pub.clone(),
                )),
                FixtureHolderBinding::Bearer => HolderBinding::BearerWithoutBinding,
            },
        },
        claimset_id: "eu.pid.v1".into(),
        domain_tags: DomainTags {
            clm: "clm".into(),
            leaf: "leaf".into(),
            node: "node".into(),
        },
        limits: CommitmentLimits {
            max_value_len: 2048,
            salt_len: 16,
        },
        qeaa_compliance: with_qeaa.then(valid_qeaa),
    };

    let mut claims = BTreeMap::new();
    claims.insert("age".into(), serde_json::json!(42));
    let issued = issue_credential(
        input,
        &claims,
        Algorithm::Ed25519,
        &issuer_priv,
        &mut OsSaltRng,
    )
    .unwrap();

    let sd_jwt = issuer_sd_jwt(
        &issued.subject_bundle.envelope_hash,
        &issuer_jwk,
        &issuer_priv,
    );
    let presentation = match holder_binding {
        FixtureHolderBinding::Key => build_sd_jwt_presentation_with_kb_binding(
            &issued.subject_bundle,
            sd_jwt,
            &["/claims/age".into()],
            &holder_jwk,
            &holder_priv,
            KbJwtBindingInput {
                nonce: "nonce-123",
                aud: "verifier.example",
                iat_unix: now_unix,
            },
        )
        .unwrap(),
        FixtureHolderBinding::Bearer => {
            build_sd_jwt_presentation(&issued.subject_bundle, sd_jwt, &["/claims/age".into()])
                .unwrap()
        }
    };

    CredentialFixture {
        presentation: Presentation::SdJwtVc(Box::new(presentation)),
        envelope: issued.envelope,
        issuer_public_key: issuer_pub,
        issuer_jwk,
        issuer_private_key: issuer_priv,
    }
}

fn issuer_sd_jwt(envelope_hash: &[u8], issuer_jwk: &Jwk, issuer_priv: &[u8]) -> String {
    let sd_payload = serde_json::json!({
        "nbf": 1,
        "exp": 9_999_999_999u64,
        "sd_hash": codec_base64url::bytes_to_base64url(envelope_hash),
    });
    encode_signed_jwt(&sd_payload, issuer_jwk, issuer_priv).unwrap()
}

fn real_sd_jwt_presentation_and_crypto_inputs(
    now_unix: u64,
) -> (Presentation, CredentialEnvelope, Vec<u8>) {
    let fixture = issue_fixture(now_unix, true, FixtureHolderBinding::Key, None);
    (
        fixture.presentation,
        fixture.envelope,
        fixture.issuer_public_key,
    )
}

fn bound_status_list() -> StatusList {
    StatusList {
        issuer: ISSUER_DID.to_string(),
        purpose: StatusPurpose::Revocation,
        issued_at: 1_719_990_000,
        next_update: 1_800_000_000,
        encoded_list: vec![0],
        length: 1,
        list_id: Some(STATUS_LIST_ID),
        signature: StatusListSignature {
            alg: StatusListAlgorithm::Ed25519,
            sig_bytes: vec![1, 2, 3],
        },
    }
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

    let status_list = bound_status_list();

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
    // A PID envelope without issuer-signed QEAA evidence; callers can no
    // longer inject QEAA evidence alongside it.
    let fixture = issue_fixture(now, false, FixtureHolderBinding::Key, None);
    let (pres, envelope, issuer_pk) = (
        fixture.presentation,
        fixture.envelope,
        fixture.issuer_public_key,
    );
    let reg = empty_registry("eu.pid.v1");

    let status_list = bound_status_list();

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
        credential_envelope: Some(&envelope),
        sd_jwt_issuer_public_key: Some(issuer_pk.as_slice()),
        sd_jwt_binding: Some(expected_sd_jwt_binding(now)),
        now_unix: now,
    })
    .unwrap_err();

    // The envelope is signed for `eu.pid.v1`, so a caller-selected claimset
    // that differs from it is rejected before policy selection.
    assert!(matches!(
        err,
        VpValidationError::PolicyRejected(errs) if errs == vec![VpPolicyError::ClaimsetNotAllowed]
    ));
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

fn validate_fixture_with(
    presentation: &Presentation,
    envelope: &CredentialEnvelope,
    issuer_public_key: &[u8],
    claimset_id: &str,
    status: Option<StatusContext<'_>>,
    binding: Option<ExpectedKbJwtBinding<'static>>,
    now: u64,
) -> Result<WebValidationResult, VpValidationError> {
    let registry = empty_registry(claimset_id);
    validate_web_presentation(WebValidationInput {
        presentation,
        claims_registry: &registry,
        claimset_id,
        status,
        credential_envelope: Some(envelope),
        sd_jwt_issuer_public_key: Some(issuer_public_key),
        sd_jwt_binding: binding,
        now_unix: now,
    })
}

fn is_rejected_with(
    result: Result<WebValidationResult, VpValidationError>,
    expected: VpPolicyError,
) -> bool {
    matches!(
        result,
        Err(VpValidationError::PolicyRejected(errors)) if errors.contains(&expected)
    )
}

#[test]
fn web_rejects_valid_sd_jwt_paired_with_swapped_envelope() {
    let now = 1_720_000_000u64;
    let presented = issue_fixture(now, true, FixtureHolderBinding::Key, None);
    // Same issuer, genuinely signed, but not the envelope committed by the
    // presented issuer SD-JWT.
    let swapped = issue_fixture(
        now,
        true,
        FixtureHolderBinding::Key,
        Some((
            presented.issuer_public_key.clone(),
            presented.issuer_private_key.clone(),
        )),
    );

    let result = validate_fixture_with(
        &presented.presentation,
        &swapped.envelope,
        &presented.issuer_public_key,
        "eu.pid.v1",
        None,
        Some(expected_sd_jwt_binding(now)),
        now,
    );
    assert!(is_rejected_with(result, VpPolicyError::ProofInvalid));
}

#[test]
fn web_rejects_envelope_signed_for_a_different_claimset() {
    let now = 1_720_000_000u64;
    let fixture = issue_fixture(now, true, FixtureHolderBinding::Key, None);
    let status_list = bound_status_list();
    let verifier = AcceptAllStatusVerifier;

    let result = validate_fixture_with(
        &fixture.presentation,
        &fixture.envelope,
        &fixture.issuer_public_key,
        "eu.pid.baseline.v1",
        Some(StatusContext {
            list: &status_list,
            index: 0,
            verifier: &verifier,
        }),
        Some(expected_sd_jwt_binding(now)),
        now,
    );
    assert!(is_rejected_with(result, VpPolicyError::ClaimsetNotAllowed));
}

#[test]
fn web_rejects_status_list_not_referenced_by_envelope() {
    let now = 1_720_000_000u64;
    let fixture = issue_fixture(now, true, FixtureHolderBinding::Key, None);
    let verifier = AcceptAllStatusVerifier;

    let mut wrong_list_id = bound_status_list();
    wrong_list_id.list_id = Some([0x24; 32]);
    let mut missing_list_id = bound_status_list();
    missing_list_id.list_id = None;
    let mut wrong_issuer = bound_status_list();
    wrong_issuer.issuer = "did:test:other-issuer".into();

    for list in [&wrong_list_id, &missing_list_id, &wrong_issuer] {
        let result = validate_fixture_with(
            &fixture.presentation,
            &fixture.envelope,
            &fixture.issuer_public_key,
            "eu.pid.v1",
            Some(StatusContext {
                list,
                index: 0,
                verifier: &verifier,
            }),
            Some(expected_sd_jwt_binding(now)),
            now,
        );
        assert!(matches!(result, Err(VpValidationError::StatusCheckFailed)));
    }
}

#[test]
fn web_rejects_bearer_credential_without_verified_holder_binding() {
    let now = 1_720_000_000u64;
    let fixture = issue_fixture(now, true, FixtureHolderBinding::Bearer, None);

    let result = validate_fixture_with(
        &fixture.presentation,
        &fixture.envelope,
        &fixture.issuer_public_key,
        "eu.pid.v1",
        None,
        None,
        now,
    );
    assert!(matches!(result, Err(VpValidationError::InvalidBinding)));
}

#[test]
fn web_rejects_binding_evaluated_at_a_different_time() {
    let now = 1_720_000_000u64;
    let fixture = issue_fixture(now, true, FixtureHolderBinding::Key, None);
    let status_list = bound_status_list();
    let verifier = AcceptAllStatusVerifier;

    let result = validate_fixture_with(
        &fixture.presentation,
        &fixture.envelope,
        &fixture.issuer_public_key,
        "eu.pid.v1",
        Some(StatusContext {
            list: &status_list,
            index: 0,
            verifier: &verifier,
        }),
        Some(expected_sd_jwt_binding(now + 1)),
        now,
    );
    assert!(is_rejected_with(result, VpPolicyError::ProofInvalid));
}

#[test]
fn web_rejects_issuer_sd_jwt_that_does_not_commit_to_envelope() {
    let now = 1_720_000_000u64;
    let fixture = issue_fixture(now, true, FixtureHolderBinding::Key, None);
    // An issuer SD-JWT whose sd_hash does not commit to the envelope.
    let unrelated_sd_jwt =
        issuer_sd_jwt(&[7u8; 32], &fixture.issuer_jwk, &fixture.issuer_private_key);
    let Presentation::SdJwtVc(original) = &fixture.presentation else {
        panic!("fixture must be SD-JWT");
    };
    let mut tampered = original.as_ref().clone();
    tampered.sd_jwt = unrelated_sd_jwt;
    tampered.envelope_hash = None;
    let tampered = Presentation::SdJwtVc(Box::new(tampered));

    let result = validate_fixture_with(
        &tampered,
        &fixture.envelope,
        &fixture.issuer_public_key,
        "eu.pid.v1",
        None,
        Some(expected_sd_jwt_binding(now)),
        now,
    );
    assert!(is_rejected_with(result, VpPolicyError::ProofInvalid));
}
