// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#[cfg(feature = "proto")]
use buffa::MessageField;
use reallyme_credential::{
    check_credential_envelope_status_command, credential_envelope_hash, credential_signing_payload,
    validate_credential_envelope, validate_credential_envelope_command,
    validate_credential_unsigned_envelope, validate_credential_with_bundle,
    validate_credential_with_evidence, AssuranceLevel, CredentialCheckCode, CredentialCheckName,
    CredentialCheckOutcome, CredentialDecision, CredentialEnvelope, CredentialError,
    CredentialEvidenceValidationInput, CredentialInvalidReason, CredentialIssuerSigner,
    CredentialIssuerVerifier, CredentialKind, CredentialRevocationVerificationInput,
    CredentialSignatureReason, CredentialStatus, CredentialStatusListPolicyInput,
    CredentialStatusListPolicyStatusInput, CredentialStatusReason, CredentialSubject,
    CredentialValidateRequest, CredentialValidationPolicy, CredentialValidityReason,
    CredentialVerificationContext, CredentialVerificationInput, HolderBinding, PartyReference,
};
#[cfg(feature = "proto")]
use reallyme_credential::{credential_envelope_from_proto, credential_envelope_to_proto};
use reallyme_credential_audit::{
    AuditInfo, IdentityProofing, IdentityProofingLevel, IssuerCredential, IssuerCredentialKind,
    KeyManagement, KeyProtection, QeaaCompliance, QeaaPolicies, QtspInfo, QtspRole,
    RevocationPolicy, StatusMethod,
};
use reallyme_credential_claims::{
    build_claims_commitment, default_commitment_domain_tags, default_commitment_limits,
    BuiltClaimsCommitment, ClaimCommitmentBuildInput, ClaimDefinition, ClaimDisclosurePolicy,
    ClaimSaltSource, ClaimType, ClaimValue, ClaimsCommitment, ClaimsError, CommitmentLimits,
    CredentialAlgorithm, DisclosureMode, DomainTags, KeyAssurance, KeyReference, PublicKeyRef,
    PublicKeyRepresentation, RawPublicKeySerialization, Signature, SubjectPrivateBundle,
    ENCODING_JCS_UTF8,
};
use reallyme_credential_status::{
    CredentialStatusError, StatusList, StatusListAlgorithm, StatusListSignature,
    StatusListVerifier, StatusPurpose,
};
use reallyme_revocation::{hybrid_fallback, vc_statuslist, StatusCheckError, StatusChecker};
use reallyme_trust_x509::{BasicConstraints, KeyUsage, QcStatements, X509Certificate};
use std::collections::BTreeMap;
use time::{Date, Month, OffsetDateTime, PrimitiveDateTime, Time};

fn sample_envelope(kind: CredentialKind) -> CredentialEnvelope {
    CredentialEnvelope {
        kind,
        profile_id: "eu.pid.v1".to_owned(),
        assurance: AssuranceLevel::High,
        issuer_reference: PartyReference::Did("did:web:issuer.example".to_owned()),
        issuer_country: "EU".to_owned(),
        valid_from: 1_750_000_000,
        valid_until: 1_760_000_000,
        status: CredentialStatus {
            status_list_url: "https://issuer.example/status/1".to_owned(),
            status_list_id: [4; 32],
            status_list_index: 7,
            purpose: StatusPurpose::Revocation,
        },
        subject: CredentialSubject {
            subject_reference: PartyReference::OpaqueIdentifier("pairwise-subject-1".to_owned()),
            holder_binding: HolderBinding::CryptographicKey(sample_key(1)),
        },
        claims_commitment: sample_commitment(),
        qeaa_compliance: matches!(kind, CredentialKind::Qeaa).then(sample_qeaa),
        issuer_signature: sample_signature(8),
    }
}

fn sample_commitment() -> ClaimsCommitment {
    ClaimsCommitment {
        merkle_root: vec![1; 32],
        claimset_id: "eu.pid.v1".to_owned(),
        hash_alg: "sha-256".to_owned(),
        value_encoding: "JCS-UTF8".to_owned(),
        domain_tags: DomainTags {
            clm: "CLM".to_owned(),
            leaf: "LEAF".to_owned(),
            node: "NODE".to_owned(),
        },
        limits: CommitmentLimits {
            max_value_len: 128,
            salt_len: 16,
        },
    }
}

fn sample_key(byte: u8) -> PublicKeyRef {
    PublicKeyRef {
        alg: CredentialAlgorithm::Ed25519,
        reference: KeyReference::DidVerificationMethod("did:web:holder.example#key-1".to_owned()),
        public_key: PublicKeyRepresentation::Raw {
            serialization: RawPublicKeySerialization::FixedWidth,
            bytes: vec![byte; 32],
        },
        assurance: KeyAssurance::None,
    }
}

fn sample_signature(byte: u8) -> Signature {
    let mut verification_key = sample_key(byte);
    verification_key.reference =
        KeyReference::DidVerificationMethod("did:web:issuer.example#key-1".to_owned());
    Signature {
        verification_key,
        raw_rs: vec![byte; 64],
    }
}

struct TestSigner {
    verification_key: PublicKeyRef,
}

fn test_signer() -> TestSigner {
    TestSigner {
        verification_key: sample_signature(0).verification_key.clone(),
    }
}

impl CredentialIssuerSigner for TestSigner {
    fn verification_key(&self) -> &PublicKeyRef {
        &self.verification_key
    }

    fn sign_credential_payload(&self, payload: &[u8]) -> Result<Vec<u8>, CredentialError> {
        if payload.is_empty() {
            return Err(CredentialError::Signature(
                CredentialSignatureReason::SigningFailed,
            ));
        }
        Ok(vec![0xA5; 64])
    }
}

struct TestVerifier {
    expected_method: &'static str,
}

impl CredentialIssuerVerifier for TestVerifier {
    fn verify_credential_payload(
        &self,
        _issuer_reference: &PartyReference,
        verification_key: &PublicKeyRef,
        payload: &[u8],
        signature: &[u8],
    ) -> Result<(), CredentialError> {
        if verification_key.reference
            != KeyReference::DidVerificationMethod(self.expected_method.to_owned())
        {
            return Err(CredentialError::Signature(
                CredentialSignatureReason::VerificationMethodMismatch,
            ));
        }
        if verification_key.alg == CredentialAlgorithm::Ed25519
            && !payload.is_empty()
            && signature == [0xA5; 64]
        {
            Ok(())
        } else {
            Err(CredentialError::Signature(
                CredentialSignatureReason::VerificationFailed,
            ))
        }
    }
}

struct TestStatusVerifier;

impl StatusListVerifier for TestStatusVerifier {
    fn verify_status_list(
        &self,
        issuer: &str,
        alg: StatusListAlgorithm,
        payload: &[u8],
        signature: &[u8],
    ) -> Result<(), CredentialStatusError> {
        if issuer == "did:web:issuer.example"
            && alg == StatusListAlgorithm::Ed25519
            && !payload.is_empty()
            && signature == [0x55; 64]
        {
            Ok(())
        } else {
            Err(CredentialStatusError::InvalidSignature)
        }
    }
}

struct StaticStatusChecker {
    result: Result<(), StatusCheckError>,
}

impl StatusChecker for StaticStatusChecker {
    fn check(&self, _cert: &X509Certificate, _now_unix: u64) -> Result<(), StatusCheckError> {
        self.result
    }
}

fn instant(day: u8) -> OffsetDateTime {
    PrimitiveDateTime::new(
        Date::from_calendar_date(2026, Month::January, day).unwrap(),
        Time::MIDNIGHT,
    )
    .assume_utc()
}

fn sample_certificate() -> X509Certificate {
    X509Certificate {
        der: vec![0x30, 0x03, 0x01],
        subject: "CN=leaf".to_owned(),
        issuer: "CN=issuer".to_owned(),
        subject_der: b"CN=leaf".to_vec(),
        issuer_der: b"CN=issuer".to_vec(),
        serial: vec![1, 2, 3],
        not_before: instant(1),
        not_after: instant(31),
        spki_der: vec![0x30, 0x02, 0x02],
        signature_algorithm_oid: "1.3.101.112".to_owned(),
        basic_constraints: Some(BasicConstraints {
            ca: false,
            path_len_constraint: None,
        }),
        key_usage: Some(KeyUsage {
            digital_signature: true,
            content_commitment: false,
            key_cert_sign: false,
            crl_sign: false,
            key_encipherment: false,
            data_encipherment: false,
            key_agreement: false,
            encipher_only: false,
            decipher_only: false,
        }),
        extended_key_usage: None,
        subject_key_identifier: Some(vec![9, 9, 9]),
        authority_key_identifier: None,
        san_dns: Vec::new(),
        san_ip: Vec::new(),
        certificate_policies: Vec::new(),
        qc_statements: QcStatements::default(),
        profile: Default::default(),
    }
}

struct DeterministicSaltSource {
    next: u8,
}

impl ClaimSaltSource for DeterministicSaltSource {
    fn fill_salt(&mut self, claim_path: &str, salt: &mut [u8]) -> Result<(), ClaimsError> {
        let path_len = u8::try_from(claim_path.len() % 251).unwrap();
        for (index, byte) in salt.iter_mut().enumerate() {
            let offset = u8::try_from(index % 251).unwrap();
            *byte = self.next.wrapping_add(path_len).wrapping_add(offset);
        }
        self.next = self.next.wrapping_add(11);
        Ok(())
    }
}

fn sample_claim_registry() -> reallyme_credential_claims::ClaimsRegistry {
    let mut claims = BTreeMap::new();
    claims.insert(
        "age".to_owned(),
        ClaimDefinition {
            claim_id: "age".to_owned(),
            claim_type: ClaimType::UnsignedInteger,
            encoding: ENCODING_JCS_UTF8.to_owned(),
            disclosure: ClaimDisclosurePolicy {
                allow_reveal: false,
                predicates: vec![DisclosureMode::Gte],
            },
        },
    );
    reallyme_credential_claims::ClaimsRegistry {
        claimset_id: "eu.pid.v1".to_owned(),
        claims,
    }
}

fn sample_claim_payload() -> ClaimValue {
    let mut values = BTreeMap::new();
    values.insert("age".to_owned(), ClaimValue::Unsigned(42));
    ClaimValue::Object(values)
}

fn sample_envelope_and_bundle(kind: CredentialKind) -> (CredentialEnvelope, SubjectPrivateBundle) {
    let registry = sample_claim_registry();
    let payload = sample_claim_payload();
    let mut salt_source = DeterministicSaltSource { next: 7 };
    let BuiltClaimsCommitment {
        commitment,
        mut bundle,
    } = build_claims_commitment(
        ClaimCommitmentBuildInput {
            registry: &registry,
            payload: &payload,
            holder_key: Some(sample_key(1)),
            envelope_hash: vec![0; 32],
            issuer_signature: sample_signature(8),
            limits: default_commitment_limits(),
            domain_tags: default_commitment_domain_tags(),
        },
        &mut salt_source,
    )
    .unwrap();

    let mut envelope = sample_envelope(kind);
    envelope.claims_commitment = commitment;
    envelope.subject.holder_binding = HolderBinding::CryptographicKey(sample_key(1));
    envelope.issuer_signature = sample_signature(8);
    bundle.envelope_hash = credential_envelope_hash(&envelope).unwrap().to_vec();
    bundle.holder_key = Some(sample_key(1));
    bundle.issuer_signature = sample_signature(8);

    (envelope, bundle)
}

fn sample_status_list(encoded_list: Vec<u8>) -> StatusList {
    StatusList {
        issuer: "did:web:issuer.example".to_owned(),
        purpose: StatusPurpose::Revocation,
        issued_at: 1_740_000_000,
        next_update: 1_770_000_000,
        encoded_list,
        length: 8,
        list_id: Some([4; 32]),
        signature: StatusListSignature {
            alg: StatusListAlgorithm::Ed25519,
            sig_bytes: vec![0x55; 64],
        },
    }
}

fn sample_qeaa() -> QeaaCompliance {
    QeaaCompliance {
        qtsp: QtspInfo {
            tsp_name: "Test QTSP".to_owned(),
            tsp_id: "EU:QTSP:123".to_owned(),
            tsp_role: QtspRole::QeaaProvider,
        },
        policies: QeaaPolicies {
            policy_id: "eu-qeaa-policy-v1".to_owned(),
            standards: vec!["ETSI EN 319 411-2".to_owned(), "ETSI TS 119 461".to_owned()],
        },
        issuer_credential: IssuerCredential {
            kind: IssuerCredentialKind::X509,
            cert_fingerprint_sha256: [7; 32],
            cert_chain_der: vec![vec![0x30, 0x03, 0x01]],
            trusted_list_ref: "EU-TSL:example".to_owned(),
            policy_oids: vec!["0.4.0.194112.1.3".to_owned()],
            qcstatements_oids: vec!["0.4.0.1862.1.1".to_owned()],
        },
        key_management: KeyManagement {
            signing_key_id: "issuer-signing-key-1".to_owned(),
            protection: KeyProtection::Qscd,
        },
        identity_proofing: IdentityProofing {
            standard: "ETSI TS 119 461".to_owned(),
            loip: IdentityProofingLevel::High,
            evidence_ref: "urn:reallyme:evidence:proofing:1".to_owned(),
            evidence_hash: [9; 32],
        },
        audit: AuditInfo {
            audit_standard: "ETSI EN 319 403-1".to_owned(),
            audit_report_ref: "urn:reallyme:audit:report:1".to_owned(),
            audit_report_hash: [3; 32],
            period_from_unix: 1_700_000_000,
            period_to_unix: 1_800_000_000,
        },
        revocation: RevocationPolicy {
            status_method: StatusMethod::StatusList,
            signing_key_id: "status-signing-key-1".to_owned(),
            max_status_age_seconds: 86_400,
        },
    }
}

#[test]
fn pid_credential_validates() {
    validate_credential_envelope(&sample_envelope(CredentialKind::Pid)).unwrap();
}

#[test]
fn qeaa_credential_validates_with_compliance() {
    validate_credential_envelope(&sample_envelope(CredentialKind::Qeaa)).unwrap();
}

#[test]
fn qeaa_credential_requires_compliance() {
    let mut envelope = sample_envelope(CredentialKind::Qeaa);
    envelope.qeaa_compliance = None;

    let err = validate_credential_envelope(&envelope).unwrap_err();

    assert_eq!(
        err,
        CredentialError::InvalidInput(CredentialInvalidReason::MissingQeaaCompliance)
    );
}

#[test]
fn pid_rejects_qeaa_compliance() {
    let mut envelope = sample_envelope(CredentialKind::Pid);
    envelope.qeaa_compliance = Some(sample_qeaa());

    let err = validate_credential_envelope(&envelope).unwrap_err();

    assert_eq!(
        err,
        CredentialError::InvalidInput(CredentialInvalidReason::UnexpectedQeaaCompliance)
    );
}

#[test]
fn rejects_invalid_validity_window() {
    let mut envelope = sample_envelope(CredentialKind::Pid);
    envelope.valid_until = envelope.valid_from;

    let err = validate_credential_envelope(&envelope).unwrap_err();

    assert_eq!(
        err,
        CredentialError::InvalidInput(CredentialInvalidReason::InvalidValidityWindow)
    );
}

#[test]
fn rejects_profile_claimset_mismatch() {
    let mut envelope = sample_envelope(CredentialKind::Pid);
    envelope.claims_commitment.claimset_id = "eu.address.v1".to_owned();

    let err = validate_credential_envelope(&envelope).unwrap_err();

    assert_eq!(
        err,
        CredentialError::InvalidInput(CredentialInvalidReason::ProfileClaimsetMismatch)
    );
}

#[test]
fn rejects_status_index_outside_canonical_integer_range() {
    let mut envelope = sample_envelope(CredentialKind::Pid);
    envelope.status.status_list_index = u64::MAX;

    let err = validate_credential_envelope(&envelope).unwrap_err();

    assert_eq!(
        err,
        CredentialError::InvalidInput(CredentialInvalidReason::InvalidStatusListIndex)
    );
}

#[test]
fn rejects_private_bundle_key_mismatch() {
    let (envelope, mut bundle) = sample_envelope_and_bundle(CredentialKind::Pid);
    bundle.holder_key = Some(sample_key(3));

    let err = validate_credential_with_bundle(&envelope, &bundle).unwrap_err();

    assert_eq!(
        err,
        CredentialError::InvalidInput(CredentialInvalidReason::PrivateBundleEnvelopeMismatch)
    );
}

#[test]
fn valid_private_bundle_binds_to_envelope_hash() {
    let (envelope, bundle) = sample_envelope_and_bundle(CredentialKind::Pid);

    validate_credential_with_bundle(&envelope, &bundle).unwrap();
}

#[test]
fn rejects_private_bundle_envelope_hash_mismatch() {
    let (envelope, mut bundle) = sample_envelope_and_bundle(CredentialKind::Pid);
    bundle.envelope_hash[0] ^= 0x01;

    let err = validate_credential_with_bundle(&envelope, &bundle).unwrap_err();

    assert_eq!(
        err,
        CredentialError::InvalidInput(CredentialInvalidReason::PrivateBundleEnvelopeMismatch)
    );
}

#[test]
fn credential_signing_payload_excludes_issuer_signature() {
    let mut first = sample_envelope(CredentialKind::Pid);
    let mut second = sample_envelope(CredentialKind::Pid);
    first.issuer_signature = sample_signature(8);
    second.issuer_signature = sample_signature(9);

    assert_eq!(
        credential_signing_payload(&first).unwrap(),
        credential_signing_payload(&second).unwrap()
    );
    assert_eq!(
        credential_envelope_hash(&first).unwrap(),
        credential_envelope_hash(&second).unwrap()
    );
}

#[test]
fn credential_signing_payload_changes_when_public_envelope_changes() {
    let first = sample_envelope(CredentialKind::Pid);
    let mut second = sample_envelope(CredentialKind::Pid);
    second.status.status_list_index = 8;

    assert_ne!(
        credential_envelope_hash(&first).unwrap(),
        credential_envelope_hash(&second).unwrap()
    );
}

#[test]
fn unsigned_envelope_can_derive_payload_before_signature_exists() {
    let mut envelope = sample_envelope(CredentialKind::Pid);
    envelope.issuer_signature.raw_rs.clear();

    validate_credential_unsigned_envelope(&envelope).unwrap();
    assert!(!credential_signing_payload(&envelope).unwrap().is_empty());
    assert_eq!(
        validate_credential_envelope(&envelope).unwrap_err(),
        CredentialError::InvalidInput(CredentialInvalidReason::InvalidIssuerSignature)
    );
}

#[test]
fn sign_and_verify_credential_with_injected_traits() {
    let mut envelope = sample_envelope(CredentialKind::Pid);
    envelope.issuer_signature.raw_rs.clear();

    reallyme_credential::sign_credential_envelope(&mut envelope, &test_signer()).unwrap();
    reallyme_credential::verify_credential_issuer_signature(
        &envelope,
        &TestVerifier {
            expected_method: "did:web:issuer.example#key-1",
        },
    )
    .unwrap();
}

#[test]
fn verify_rejects_verification_method_mismatch() {
    let mut envelope = sample_envelope(CredentialKind::Pid);
    reallyme_credential::sign_credential_envelope(&mut envelope, &test_signer()).unwrap();

    let err = reallyme_credential::verify_credential_issuer_signature(
        &envelope,
        &TestVerifier {
            expected_method: "did:web:issuer.example#wrong",
        },
    )
    .unwrap_err();

    assert_eq!(
        err,
        CredentialError::Signature(CredentialSignatureReason::VerificationMethodMismatch)
    );
}

#[test]
fn credential_status_verifies_against_matching_status_list() {
    let envelope = sample_envelope(CredentialKind::Pid);
    let status_list = sample_status_list(vec![0]);

    reallyme_credential::verify_credential_status(
        &envelope,
        &status_list,
        1_750_000_000,
        &TestStatusVerifier,
    )
    .unwrap();
}

#[test]
fn credential_status_rejects_revoked_bit() {
    let envelope = sample_envelope(CredentialKind::Pid);
    let status_list = sample_status_list(vec![0b1000_0000]);

    let err = reallyme_credential::verify_credential_status(
        &envelope,
        &status_list,
        1_750_000_000,
        &TestStatusVerifier,
    )
    .unwrap_err();

    assert_eq!(
        err,
        CredentialError::Status(CredentialStatusReason::Revoked)
    );
}

#[test]
fn credential_status_rejects_expired_list() {
    let envelope = sample_envelope(CredentialKind::Pid);
    let status_list = sample_status_list(vec![0]);

    let err = reallyme_credential::verify_credential_status(
        &envelope,
        &status_list,
        1_780_000_000,
        &TestStatusVerifier,
    )
    .unwrap_err();

    assert_eq!(
        err,
        CredentialError::Status(CredentialStatusReason::Expired)
    );
}

#[test]
fn credential_status_rejects_not_yet_valid_list() {
    let envelope = sample_envelope(CredentialKind::Pid);
    let status_list = sample_status_list(vec![0]);

    let err = reallyme_credential::verify_credential_status(
        &envelope,
        &status_list,
        1_739_999_999,
        &TestStatusVerifier,
    )
    .unwrap_err();

    assert_eq!(
        err,
        CredentialError::Status(CredentialStatusReason::NotYetValid)
    );
}

#[test]
fn credential_status_rejects_status_pointer_mismatch() {
    let envelope = sample_envelope(CredentialKind::Pid);
    let mut status_list = sample_status_list(vec![0]);
    status_list.list_id = Some([5; 32]);

    let err = reallyme_credential::verify_credential_status(
        &envelope,
        &status_list,
        1_750_000_000,
        &TestStatusVerifier,
    )
    .unwrap_err();

    assert_eq!(
        err,
        CredentialError::Status(CredentialStatusReason::StatusPointerMismatch)
    );
}

#[test]
fn verify_credential_composes_signature_and_status() {
    let mut envelope = sample_envelope(CredentialKind::Pid);
    let status_list = sample_status_list(vec![0]);
    reallyme_credential::sign_credential_envelope(&mut envelope, &test_signer()).unwrap();

    reallyme_credential::verify_credential(&CredentialVerificationInput {
        envelope: &envelope,
        issuer_verifier: &TestVerifier {
            expected_method: "did:web:issuer.example#key-1",
        },
        status_list: &status_list,
        status_verifier: &TestStatusVerifier,
        now_unix: 1_750_000_000,
    })
    .unwrap();
}

#[test]
fn credential_validate_command_is_indeterminate_without_required_evidence() {
    let (envelope, _bundle) = sample_envelope_and_bundle(CredentialKind::Pid);
    let result = reallyme_credential::validate_credential_command(CredentialValidateRequest {
        credential: envelope,
        subject_bundle: None,
        verification_context: CredentialVerificationContext {
            now_unix: 1_750_000_000,
            audience: None,
            nonce: None,
        },
        policy: CredentialValidationPolicy::default(),
        checks: Vec::new(),
    });

    assert!(!result.valid);
    assert_eq!(result.decision, CredentialDecision::Indeterminate);
    assert!(result.checks.iter().any(|check| {
        check.name == CredentialCheckName::Signature
            && check.outcome == CredentialCheckOutcome::Indeterminate
            && check.code == CredentialCheckCode::EvidenceRequired
    }));
    assert!(result.checks.iter().any(|check| {
        check.name == CredentialCheckName::Status
            && check.outcome == CredentialCheckOutcome::Indeterminate
            && check.code == CredentialCheckCode::EvidenceRequired
    }));

    let (key_binding_envelope, _bundle) = sample_envelope_and_bundle(CredentialKind::Pid);
    let key_binding_result =
        reallyme_credential::validate_credential_command(CredentialValidateRequest {
            credential: key_binding_envelope,
            subject_bundle: None,
            verification_context: CredentialVerificationContext {
                now_unix: 1_750_000_000,
                audience: None,
                nonce: None,
            },
            policy: CredentialValidationPolicy {
                require_signature: false,
                require_status: false,
                require_holder_binding: false,
                require_trust_chain: false,
                require_policy: false,
            },
            checks: vec![CredentialCheckName::KeyBinding],
        });

    assert!(!key_binding_result.valid);
    assert_eq!(
        key_binding_result.decision,
        CredentialDecision::Indeterminate
    );
    assert!(key_binding_result.checks.iter().any(|check| {
        check.name == CredentialCheckName::KeyBinding
            && check.outcome == CredentialCheckOutcome::Indeterminate
    }));
    assert!(key_binding_result
        .checks
        .iter()
        .all(|check| check.name == CredentialCheckName::KeyBinding || check.mandatory));
}
