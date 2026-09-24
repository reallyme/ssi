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
//! Test coverage for this crate.

use identity_revocation_core::{StatusCheckError, StatusChecker};

use reallyme_trust_core::{
    evaluate_trust, evaluate_trust_decision, CertificatePosition, CertificateStatus,
    CertificateStatusPolicy, DirectTrustEntry, SignatureVerifier, SignatureVerifyError,
    StatusRequirement, TrustAnchorKind, TrustConfig, TrustError, TrustEvaluationContext,
    TrustOutcome, TrustPolicyId, TrustPurpose, TrustResourceLimit, TrustSourceEvidence,
    MAX_DIRECT_TRUST_ENTRIES, MAX_TRUST_ROOTS,
};

use envelopes_x509::{
    model::{BasicConstraints, KeyUsage, X509Certificate, X509Chain},
    policy::{TrustAnchorRequirement, X509Policy},
};

use time::OffsetDateTime;

#[path = "trust_eval/path_validation_tests.rs"]
mod path_validation_tests;

//
// ─────────────────────────────────────────────
// Test helpers
// ─────────────────────────────────────────────
//

fn mock_cert(
    subject: &str,
    issuer: &str,
    is_ca: bool,
    ski: Option<Vec<u8>>,
    aki: Option<Vec<u8>>,
) -> X509Certificate {
    X509Certificate {
        der: subject.as_bytes().to_vec(),
        subject: subject.to_string(),
        issuer: issuer.to_string(),
        serial: vec![1, 2, 3],

        not_before: OffsetDateTime::UNIX_EPOCH,
        not_after: OffsetDateTime::UNIX_EPOCH + time::Duration::days(365),

        spki_der: vec![],
        signature_algorithm_oid: "1.2.3.4".into(),

        basic_constraints: Some(BasicConstraints {
            ca: is_ca,
            path_len_constraint: None,
        }),

        key_usage: Some(KeyUsage {
            digital_signature: true,
            content_commitment: false,
            key_encipherment: false,
            data_encipherment: false,
            key_cert_sign: is_ca,
            crl_sign: is_ca,
            key_agreement: false,
            encipher_only: false,
            decipher_only: false,
        }),

        extended_key_usage: None,
        subject_key_identifier: ski,
        authority_key_identifier: aki,

        san_dns: vec![],
        san_ip: vec![],

        certificate_policies: vec![],
        qc_statements: Default::default(),
        profile: Default::default(),
    }
}

//
// ─────────────────────────────────────────────
// Mock backends
// ─────────────────────────────────────────────
//

struct AllowAllSignatures;
impl SignatureVerifier for AllowAllSignatures {
    fn verify_chain(
        &self,
        _chain: &X509Chain,
        _now: OffsetDateTime,
    ) -> Result<(), SignatureVerifyError> {
        Ok(())
    }
}

struct RejectAllSignatures;
impl SignatureVerifier for RejectAllSignatures {
    fn verify_chain(
        &self,
        _chain: &X509Chain,
        _now: OffsetDateTime,
    ) -> Result<(), SignatureVerifyError> {
        Err(SignatureVerifyError::InvalidSignature)
    }
}

struct AllowAllStatus;
impl StatusChecker for AllowAllStatus {
    fn check(&self, _cert: &X509Certificate, _now_unix: u64) -> Result<(), StatusCheckError> {
        Ok(())
    }
}

struct RejectAllStatus;
impl StatusChecker for RejectAllStatus {
    fn check(&self, _cert: &X509Certificate, _now_unix: u64) -> Result<(), StatusCheckError> {
        Err(StatusCheckError::Revoked)
    }
}

struct StaticStatus(StatusCheckError);
impl StatusChecker for StaticStatus {
    fn check(&self, _cert: &X509Certificate, _now_unix: u64) -> Result<(), StatusCheckError> {
        Err(self.0)
    }
}

struct MixedUnknownAndRevokedStatus {
    revoked_der: Vec<u8>,
}

impl StatusChecker for MixedUnknownAndRevokedStatus {
    fn check(&self, cert: &X509Certificate, _now_unix: u64) -> Result<(), StatusCheckError> {
        if cert.der == self.revoked_der {
            Err(StatusCheckError::Revoked)
        } else {
            Err(StatusCheckError::Unknown)
        }
    }
}

struct RejectRoot {
    der: Vec<u8>,
}
impl SignatureVerifier for RejectRoot {
    fn verify_chain(
        &self,
        chain: &X509Chain,
        _now: OffsetDateTime,
    ) -> Result<(), SignatureVerifyError> {
        match chain.certs.last() {
            Some(root) if root.der == self.der => Err(SignatureVerifyError::InvalidSignature),
            Some(_) => Ok(()),
            None => Err(SignatureVerifyError::BackendFailure),
        }
    }
}

fn config(root: X509Certificate) -> TrustConfig {
    TrustConfig {
        trust_roots: vec![root],
        now: OffsetDateTime::UNIX_EPOCH,
        policy: X509Policy {
            trust_anchor_requirement: TrustAnchorRequirement::Rfc5280Ca,
            ..Default::default()
        },
        link_policy: Default::default(),
        evaluation: Default::default(),
        direct_trust: Vec::new(),
    }
}

#[test]
fn trust_configuration_collections_are_bounded_in_core() {
    let leaf = mock_cert("CN=Leaf", "CN=Root", false, None, None);
    let root = mock_cert("CN=Root", "CN=Root", true, None, None);
    let excessive_root_count = MAX_TRUST_ROOTS
        .checked_add(1)
        .expect("test bound fits usize");
    let mut too_many_roots = config(root.clone());
    too_many_roots.trust_roots = vec![root; excessive_root_count];
    assert!(matches!(
        evaluate_trust_decision(
            std::slice::from_ref(&leaf),
            &too_many_roots,
            &AllowAllSignatures,
            None,
        ),
        Err(TrustError::ResourceLimit(
            TrustResourceLimit::TooManyTrustRoots
        ))
    ));

    let source = TrustSourceEvidence {
        source_id: [0x11; 32],
        snapshot_id: [0x22; 32],
    };
    let direct_entry = DirectTrustEntry {
        certificate: leaf.clone(),
        purpose: TrustPurpose::Generic,
        policy_id: TrustPolicyId::GenericX509V1,
        source,
    };
    let excessive_direct_count = MAX_DIRECT_TRUST_ENTRIES
        .checked_add(1)
        .expect("test bound fits usize");
    let too_many_direct = TrustConfig {
        trust_roots: Vec::new(),
        now: OffsetDateTime::UNIX_EPOCH,
        policy: X509Policy::default(),
        link_policy: Default::default(),
        evaluation: TrustEvaluationContext {
            source: Some(source),
            ..Default::default()
        },
        direct_trust: vec![direct_entry; excessive_direct_count],
    };
    assert!(matches!(
        evaluate_trust_decision(&[leaf], &too_many_direct, &AllowAllSignatures, None),
        Err(TrustError::ResourceLimit(
            TrustResourceLimit::TooManyDirectTrustEntries
        ))
    ));
}

//
// ─────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────
//

#[test]
fn accepts_valid_chain() {
    let root_ski = vec![0xAA];
    let intermediate_ski = vec![0xBB];

    let leaf = mock_cert(
        "CN=Leaf",
        "CN=Intermediate",
        false,
        None,
        Some(intermediate_ski.clone()),
    );

    let intermediate = mock_cert(
        "CN=Intermediate",
        "CN=Root",
        true,
        Some(intermediate_ski),
        Some(root_ski.clone()),
    );

    let root = mock_cert("CN=Root", "CN=Root", true, Some(root_ski), None);

    let cfg = TrustConfig {
        trust_roots: vec![root],
        now: OffsetDateTime::UNIX_EPOCH,
        policy: X509Policy::default(),
        link_policy: Default::default(),
        evaluation: Default::default(),
        direct_trust: Vec::new(),
    };

    let presented = vec![leaf, intermediate];

    let decision = evaluate_trust(&presented, &cfg, &AllowAllSignatures, Some(&AllowAllStatus))
        .expect("trust evaluation should succeed");

    assert!(decision.accepted);
    assert!(decision.chain.is_some());
}

#[test]
fn rejects_invalid_signature() {
    let root_ski = vec![0xAA];

    let leaf = mock_cert("CN=Leaf", "CN=Root", false, None, Some(root_ski.clone()));

    let root = mock_cert("CN=Root", "CN=Root", true, Some(root_ski), None);

    let cfg = TrustConfig {
        trust_roots: vec![root],
        now: OffsetDateTime::UNIX_EPOCH,
        policy: X509Policy::default(),
        link_policy: Default::default(),
        evaluation: Default::default(),
        direct_trust: Vec::new(),
    };

    let presented = vec![leaf];

    let err = evaluate_trust(&presented, &cfg, &RejectAllSignatures, None).unwrap_err();

    assert_eq!(err, TrustError::InvalidSignature);
}

#[test]
fn rejects_forged_leaf_reusing_trusted_anchor_subject_dn() {
    let root_ski = vec![0xAA];
    let mut forged_leaf = mock_cert(
        "CN=Trusted Root",
        "CN=Trusted Root",
        false,
        None,
        Some(root_ski.clone()),
    );
    forged_leaf.der = b"forged-leaf-with-reused-subject-dn".to_vec();
    let mut configured_root = mock_cert(
        "CN=Trusted Root",
        "CN=Trusted Root",
        true,
        Some(root_ski),
        None,
    );
    configured_root.der = b"configured-trust-anchor".to_vec();
    let cfg = config(configured_root);

    // RFC 5280 §6 requires cryptographic validation to the selected trust
    // anchor. Subject DN equality is only a path-building hint and must not
    // bypass the child-to-anchor signature check (CVE-2026-75522).
    let decision = evaluate_trust_decision(&[forged_leaf], &cfg, &RejectAllSignatures, None)
        .expect("trust evaluation returns a typed rejection");

    assert_eq!(decision.outcome, TrustOutcome::Rejected);
    assert!(!decision.accepted);
    assert!(decision.chain.is_none());
    assert!(decision
        .failures
        .contains(&reallyme_trust_core::TrustFailureReason::Signature));
    assert!(decision.evidence.trust_anchor.is_none());
}

#[test]
fn rejects_revoked_certificate() {
    let root_ski = vec![0xAA];

    let leaf = mock_cert("CN=Leaf", "CN=Root", false, None, Some(root_ski.clone()));

    let root = mock_cert("CN=Root", "CN=Root", true, Some(root_ski), None);

    let cfg = TrustConfig {
        trust_roots: vec![root],
        now: OffsetDateTime::UNIX_EPOCH,
        policy: X509Policy::default(),
        link_policy: Default::default(),
        evaluation: Default::default(),
        direct_trust: Vec::new(),
    };

    let presented = vec![leaf];

    let err = evaluate_trust(
        &presented,
        &cfg,
        &AllowAllSignatures,
        Some(&RejectAllStatus),
    )
    .unwrap_err();

    assert_eq!(err, TrustError::Revoked);
}

#[test]
fn rejects_leaf_ca_violation() {
    let root_ski = vec![0xAA];

    let leaf = mock_cert(
        "CN=Leaf",
        "CN=Root",
        true, // ❌ leaf is CA
        None,
        Some(root_ski.clone()),
    );

    let root = mock_cert("CN=Root", "CN=Root", true, Some(root_ski), None);

    let cfg = TrustConfig {
        trust_roots: vec![root],
        now: OffsetDateTime::UNIX_EPOCH,
        policy: X509Policy {
            require_leaf_not_ca: true,
            ..Default::default()
        },
        link_policy: Default::default(),
        evaluation: Default::default(),
        direct_trust: Vec::new(),
    };

    let presented = vec![leaf];

    let err = evaluate_trust(&presented, &cfg, &AllowAllSignatures, None).unwrap_err();

    assert_eq!(err, TrustError::NoValidPath);
}

#[test]
fn a_bad_first_root_does_not_abort_a_later_valid_root() {
    let root_ski = vec![0xAA];
    let leaf = mock_cert("CN=Leaf", "CN=Root", false, None, Some(root_ski.clone()));
    let mut bad_root = mock_cert("CN=Root", "CN=Root", true, Some(root_ski.clone()), None);
    bad_root.der = b"a-bad-root".to_vec();
    let mut good_root = mock_cert("CN=Root", "CN=Root", true, Some(root_ski), None);
    good_root.der = b"z-good-root".to_vec();
    let verifier = RejectRoot {
        der: bad_root.der.clone(),
    };
    let mut cfg = config(bad_root);
    cfg.trust_roots.push(good_root);

    let decision = evaluate_trust_decision(&[leaf], &cfg, &verifier, None).unwrap();

    assert_eq!(decision.outcome, TrustOutcome::Trusted);
    assert_eq!(decision.evidence.trust_anchor.unwrap().configured_index, 1);
}

#[test]
fn builds_a_deterministic_path_from_unordered_intermediates() {
    let root_ski = vec![0xA0];
    let upper_ski = vec![0xA1];
    let lower_ski = vec![0xA2];
    let leaf = mock_cert("CN=Leaf", "CN=Lower", false, None, Some(lower_ski.clone()));
    let lower = mock_cert(
        "CN=Lower",
        "CN=Upper",
        true,
        Some(lower_ski),
        Some(upper_ski.clone()),
    );
    let upper = mock_cert(
        "CN=Upper",
        "CN=Root",
        true,
        Some(upper_ski),
        Some(root_ski.clone()),
    );
    let root = mock_cert("CN=Root", "CN=Root", true, Some(root_ski), None);
    let cfg = config(root);

    let decision =
        evaluate_trust_decision(&[leaf, upper, lower], &cfg, &AllowAllSignatures, None).unwrap();

    let chain = decision.chain.unwrap();
    let subjects = chain
        .certs
        .iter()
        .map(|certificate| certificate.subject.as_str())
        .collect::<Vec<_>>();
    assert_eq!(subjects, ["CN=Leaf", "CN=Lower", "CN=Upper", "CN=Root"]);
}

#[test]
fn path_search_work_exhaustion_is_indeterminate() {
    let shared_key_id = vec![0xA5];
    let leaf = mock_cert(
        "CN=Loop",
        "CN=Loop",
        false,
        None,
        Some(shared_key_id.clone()),
    );
    let mut presented = vec![leaf];
    for discriminator in 0_u8..8 {
        let mut candidate = mock_cert(
            "CN=Loop",
            "CN=Loop",
            true,
            Some(shared_key_id.clone()),
            Some(shared_key_id.clone()),
        );
        candidate.der = vec![discriminator.checked_add(1).expect("test range is bounded")];
        presented.push(candidate);
    }
    let root = mock_cert("CN=Root", "CN=Root", true, Some(vec![0xFF]), None);
    let cfg = config(root);

    let decision = evaluate_trust_decision(&presented, &cfg, &AllowAllSignatures, None).unwrap();

    assert_eq!(decision.outcome, TrustOutcome::Indeterminate);
    assert!(decision
        .failures
        .contains(&reallyme_trust_core::TrustFailureReason::PathSearchLimit));
}

#[test]
fn normalizes_a_presented_duplicate_of_the_configured_root() {
    let root_ski = vec![0xAA];
    let leaf = mock_cert("CN=Leaf", "CN=Root", false, None, Some(root_ski.clone()));
    let root = mock_cert("CN=Root", "CN=Root", true, Some(root_ski), None);
    let cfg = config(root.clone());

    let decision = evaluate_trust_decision(&[leaf, root], &cfg, &AllowAllSignatures, None).unwrap();

    assert_eq!(decision.outcome, TrustOutcome::Trusted);
    assert_eq!(decision.chain.unwrap().certs.len(), 2);
}

#[test]
fn preserves_unknown_status_as_indeterminate_evidence() {
    let root_ski = vec![0xAA];
    let leaf = mock_cert("CN=Leaf", "CN=Root", false, None, Some(root_ski.clone()));
    let root = mock_cert("CN=Root", "CN=Root", true, Some(root_ski), None);
    let mut cfg = config(root);
    cfg.evaluation.status_policy = CertificateStatusPolicy {
        leaf: StatusRequirement::Required,
        intermediates: StatusRequirement::Exempt,
        trust_anchor: StatusRequirement::Exempt,
    };

    let decision = evaluate_trust_decision(
        &[leaf],
        &cfg,
        &AllowAllSignatures,
        Some(&StaticStatus(StatusCheckError::Unknown)),
    )
    .unwrap();

    assert_eq!(decision.outcome, TrustOutcome::Indeterminate);
    assert_eq!(decision.evidence.certificate_status.len(), 2);
    assert_eq!(
        decision.evidence.certificate_status[0].position,
        CertificatePosition::Leaf
    );
    assert_eq!(
        decision.evidence.certificate_status[0].status,
        CertificateStatus::Unknown
    );
    assert_eq!(
        decision.evidence.certificate_status[1].status,
        CertificateStatus::Exempt
    );
}

#[test]
fn preserves_not_yet_valid_and_invalid_signature_as_distinct_status_failures() {
    let cases = [
        (
            StatusCheckError::NotYetValid,
            CertificateStatus::NotYetValid,
            reallyme_trust_core::TrustFailureReason::StatusNotYetValid,
        ),
        (
            StatusCheckError::InvalidSignature,
            CertificateStatus::InvalidSignature,
            reallyme_trust_core::TrustFailureReason::StatusInvalidSignature,
        ),
    ];

    for (status_error, expected_status, expected_failure) in cases {
        let root_ski = vec![0xAA];
        let leaf = mock_cert("CN=Leaf", "CN=Root", false, None, Some(root_ski.clone()));
        let root = mock_cert("CN=Root", "CN=Root", true, Some(root_ski), None);
        let mut cfg = config(root);
        cfg.evaluation.status_policy.leaf = StatusRequirement::Required;

        let decision = evaluate_trust_decision(
            &[leaf],
            &cfg,
            &AllowAllSignatures,
            Some(&StaticStatus(status_error)),
        )
        .expect("status evaluation must return a typed decision");

        assert_eq!(decision.outcome, TrustOutcome::Indeterminate);
        assert_eq!(
            decision.evidence.certificate_status[0].status,
            expected_status
        );
        assert!(decision.failures.contains(&expected_failure));
    }
}

#[test]
fn conclusive_revocation_dominates_indeterminate_status_on_the_same_path() {
    let root_ski = vec![0xAA];
    let leaf = mock_cert("CN=Leaf", "CN=Root", false, None, Some(root_ski.clone()));
    let root = mock_cert("CN=Root", "CN=Root", true, Some(root_ski), None);
    let mut cfg = config(root.clone());
    cfg.evaluation.status_policy = CertificateStatusPolicy {
        leaf: StatusRequirement::Required,
        intermediates: StatusRequirement::Required,
        trust_anchor: StatusRequirement::Required,
    };

    let decision = evaluate_trust_decision(
        &[leaf],
        &cfg,
        &AllowAllSignatures,
        Some(&MixedUnknownAndRevokedStatus {
            revoked_der: root.der.clone(),
        }),
    )
    .expect("status evaluation must return a decision");

    assert_eq!(decision.outcome, TrustOutcome::Rejected);
    assert!(decision
        .failures
        .contains(&reallyme_trust_core::TrustFailureReason::StatusRevoked));
    assert!(decision
        .failures
        .contains(&reallyme_trust_core::TrustFailureReason::StatusUnknown));
}

#[test]
fn direct_end_entity_trust_is_exact_and_context_scoped() {
    let leaf = mock_cert("CN=Direct", "CN=Direct", false, None, None);
    let source = TrustSourceEvidence {
        source_id: [7; 32],
        snapshot_id: [8; 32],
    };
    let cfg = TrustConfig {
        trust_roots: Vec::new(),
        now: OffsetDateTime::UNIX_EPOCH,
        policy: X509Policy::default(),
        link_policy: Default::default(),
        evaluation: TrustEvaluationContext {
            purpose: TrustPurpose::WalletAttestationIssuer,
            policy_id: TrustPolicyId::WalletAttestationIssuerV1,
            status_policy: CertificateStatusPolicy {
                leaf: StatusRequirement::Exempt,
                intermediates: StatusRequirement::Exempt,
                trust_anchor: StatusRequirement::Exempt,
            },
            source: Some(source),
        },
        direct_trust: vec![DirectTrustEntry {
            certificate: leaf.clone(),
            purpose: TrustPurpose::WalletAttestationIssuer,
            policy_id: TrustPolicyId::WalletAttestationIssuerV1,
            source,
        }],
    };

    let decision = evaluate_trust_decision(&[leaf], &cfg, &RejectAllSignatures, None).unwrap();

    assert_eq!(decision.outcome, TrustOutcome::Trusted);
    assert_eq!(decision.evidence.source, Some(source));
    assert_eq!(
        decision.evidence.trust_anchor.unwrap().kind,
        TrustAnchorKind::DirectEndEntity
    );
}

#[test]
fn direct_end_entity_trust_rejects_a_different_policy_context() {
    let leaf = mock_cert("CN=Direct", "CN=Direct", false, None, None);
    let mut cfg = TrustConfig {
        trust_roots: Vec::new(),
        now: OffsetDateTime::UNIX_EPOCH,
        policy: X509Policy::default(),
        link_policy: Default::default(),
        evaluation: TrustEvaluationContext {
            purpose: TrustPurpose::WalletAttestationIssuer,
            policy_id: TrustPolicyId::WalletAttestationIssuerV1,
            source: Some(TrustSourceEvidence {
                source_id: [7; 32],
                snapshot_id: [8; 32],
            }),
            ..Default::default()
        },
        direct_trust: vec![DirectTrustEntry {
            certificate: leaf.clone(),
            purpose: TrustPurpose::WalletAttestationIssuer,
            policy_id: TrustPolicyId::WalletAttestationIssuerV1,
            source: TrustSourceEvidence {
                source_id: [7; 32],
                snapshot_id: [8; 32],
            },
        }],
    };
    cfg.evaluation.policy_id = TrustPolicyId::EuQeaaV1;

    let result =
        evaluate_trust_decision(std::slice::from_ref(&leaf), &cfg, &AllowAllSignatures, None);

    assert_eq!(result.err(), Some(TrustError::PurposePolicyMismatch));
}

#[test]
fn direct_end_entity_trust_does_not_cross_eudi_purpose_boundaries() {
    let leaf = mock_cert("CN=EUDI", "CN=EUDI", false, None, None);
    let source = TrustSourceEvidence {
        source_id: [11; 32],
        snapshot_id: [12; 32],
    };
    let cfg = TrustConfig {
        trust_roots: Vec::new(),
        now: OffsetDateTime::UNIX_EPOCH,
        policy: X509Policy::default(),
        link_policy: Default::default(),
        evaluation: TrustEvaluationContext {
            purpose: TrustPurpose::EudiWalletProviderAttestation,
            policy_id: TrustPolicyId::EtsiTs1194126WalletProviderV1,
            status_policy: CertificateStatusPolicy {
                leaf: StatusRequirement::Exempt,
                intermediates: StatusRequirement::Exempt,
                trust_anchor: StatusRequirement::Exempt,
            },
            source: Some(source),
        },
        direct_trust: vec![DirectTrustEntry {
            certificate: leaf.clone(),
            purpose: TrustPurpose::PidIssuance,
            policy_id: TrustPolicyId::EtsiTs1194126PidProviderV1,
            source,
        }],
    };

    let decision = evaluate_trust_decision(&[leaf], &cfg, &RejectAllSignatures, None).unwrap();

    assert_eq!(decision.outcome, TrustOutcome::Rejected);
    assert!(!decision.accepted);
}

#[test]
fn direct_end_entity_trust_rejects_a_different_source_snapshot() {
    let leaf = mock_cert("CN=Direct", "CN=Direct", false, None, None);
    let mut cfg = TrustConfig {
        trust_roots: Vec::new(),
        now: OffsetDateTime::UNIX_EPOCH,
        policy: X509Policy::default(),
        link_policy: Default::default(),
        evaluation: TrustEvaluationContext {
            purpose: TrustPurpose::WalletAttestationIssuer,
            policy_id: TrustPolicyId::WalletAttestationIssuerV1,
            source: Some(TrustSourceEvidence {
                source_id: [7; 32],
                snapshot_id: [8; 32],
            }),
            ..Default::default()
        },
        direct_trust: vec![DirectTrustEntry {
            certificate: leaf.clone(),
            purpose: TrustPurpose::WalletAttestationIssuer,
            policy_id: TrustPolicyId::WalletAttestationIssuerV1,
            source: TrustSourceEvidence {
                source_id: [7; 32],
                snapshot_id: [9; 32],
            },
        }],
    };

    let decision =
        evaluate_trust_decision(std::slice::from_ref(&leaf), &cfg, &AllowAllSignatures, None)
            .unwrap();

    assert_eq!(decision.outcome, TrustOutcome::Rejected);
    assert!(!decision.accepted);

    cfg.evaluation.source = None;
    let decision = evaluate_trust_decision(&[leaf], &cfg, &AllowAllSignatures, None).unwrap();
    assert_eq!(decision.outcome, TrustOutcome::Rejected);
    assert!(!decision.accepted);
}
