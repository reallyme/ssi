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

use reallyme_credential::committed::{
    canonical::canonical_credential_bytes,
    model::{
        AssuranceLevel, ClaimsCommitment, CommitmentLimits, CredentialAlgorithm,
        CredentialEnvelope, CredentialKind, CredentialStatus, CredentialSubject, DomainTags,
        HolderBinding, KeyAssurance, KeyReference, PartyReference, PublicKeyRef,
        PublicKeyRepresentation, RawPublicKeySerialization, Signature, StatusPurpose,
    },
};

fn sample_envelope() -> CredentialEnvelope {
    CredentialEnvelope {
        kind: CredentialKind::Pid,
        profile_id: "pid-basic".into(),
        assurance: AssuranceLevel::Substantial,

        issuer_reference: PartyReference::Did("did:test:issuer".into()),
        issuer_country: "EU".into(),

        valid_from: 1_700_000_000,
        valid_until: 1_800_000_000,

        status: CredentialStatus {
            status_list_url: "https://example.com/status".into(),
            status_list_id: [0u8; 32],
            status_list_index: 42,
            purpose: StatusPurpose::Revocation,
        },

        subject: CredentialSubject {
            subject_reference: PartyReference::Did("did:test:subject".into()),
            holder_binding: HolderBinding::CryptographicKey(p256_key("did:test:subject#key-1", 1)),
        },

        claims_commitment: ClaimsCommitment {
            merkle_root: vec![9u8; 32],
            claimset_id: "pid-basic".into(),
            hash_alg: "sha-256".into(),
            value_encoding: "RM-CV-JCS-V1".into(),
            domain_tags: DomainTags {
                clm: "CLM1".into(),
                leaf: "LEAF1".into(),
                node: "NODE1".into(),
            },
            limits: CommitmentLimits {
                max_value_len: 64,
                salt_len: 16,
            },
        },

        qeaa_compliance: None,

        issuer_signature: Signature {
            verification_key: p256_key("did:test:issuer#key-1", 2),
            raw_rs: vec![7u8; 64],
        },
    }
}

fn p256_key(did_url: &str, marker: u8) -> PublicKeyRef {
    PublicKeyRef {
        alg: CredentialAlgorithm::P256,
        reference: KeyReference::DidVerificationMethod(did_url.into()),
        public_key: PublicKeyRepresentation::Raw {
            serialization: RawPublicKeySerialization::Sec1Uncompressed,
            bytes: vec![marker; 65],
        },
        assurance: KeyAssurance::None,
    }
}

fn sample_qeaa() -> reallyme_credential_audit::QeaaCompliance {
    use reallyme_credential_audit::{
        AuditInfo, IdentityProofing, IdentityProofingLevel, IssuerCredential, KeyManagement,
        QeaaCompliance, QeaaPolicies, QtspInfo, RevocationPolicy, StatusMethod,
    };

    QeaaCompliance {
        qtsp: QtspInfo {
            tsp_name: "ReallyMe QTSP".to_string(),
            tsp_id: "RM-QTSP-1".to_string(),
            tsp_role: reallyme_credential_audit::QtspRole::QeaaProvider,
        },
        policies: QeaaPolicies {
            policy_id: "urn:eu:eidas:qeaa:policy:1".to_string(),
            standards: vec!["eIDAS2".to_string()],
        },
        issuer_credential: IssuerCredential {
            kind: reallyme_credential_audit::IssuerCredentialKind::X509,
            cert_fingerprint_sha256: [7u8; 32],
            cert_chain_der: vec![vec![0x30, 0x82, 0x01, 0x0a]],
            trusted_list_ref: "https://example.com/tsl.xml".to_string(),
            policy_oids: vec!["0.4.0.194112.1.3".to_string()],
            qcstatements_oids: vec!["0.4.0.1862.1.6".to_string()],
        },
        key_management: KeyManagement {
            signing_key_id: "kid-1".to_string(),
            protection: reallyme_credential_audit::KeyProtection::Hsm,
        },
        identity_proofing: IdentityProofing {
            standard: "ETSI TS 119 461".to_string(),
            loip: IdentityProofingLevel::High,
            evidence_ref: "urn:proof:evidence:1".to_string(),
            evidence_hash: [9u8; 32],
        },
        audit: AuditInfo {
            audit_standard: "ISO-19011".to_string(),
            audit_report_ref: "urn:audit:report:1".to_string(),
            audit_report_hash: [11u8; 32],
            period_from_unix: 1_700_000_000,
            period_to_unix: 1_800_000_000,
        },
        revocation: RevocationPolicy {
            status_method: StatusMethod::StatusList,
            signing_key_id: "kid-status-1".to_string(),
            max_status_age_seconds: 3600,
        },
    }
}

#[test]
fn canonical_bytes_are_deterministic() {
    let env = sample_envelope();

    let a = canonical_credential_bytes(&env).unwrap();
    let b = canonical_credential_bytes(&env).unwrap();

    assert_eq!(a, b);
}

#[test]
fn canonical_bytes_ignore_signature_field() {
    let env1 = sample_envelope();
    let mut env2 = sample_envelope();

    // Change issuer signature
    env2.issuer_signature.raw_rs = vec![9u8; 64];

    let a = canonical_credential_bytes(&env1).unwrap();
    let b = canonical_credential_bytes(&env2).unwrap();

    // Signature must NOT affect canonical bytes
    assert_eq!(a, b);
}

#[test]
fn canonical_bytes_with_qeaa_are_stable_and_non_empty() {
    let mut env = sample_envelope();
    env.kind = CredentialKind::Qeaa;
    env.qeaa_compliance = Some(sample_qeaa());

    let a = canonical_credential_bytes(&env).expect("qeaa canonicalization should succeed");
    let b = canonical_credential_bytes(&env).expect("qeaa canonicalization should succeed");

    assert!(!a.is_empty());
    assert_eq!(a, b);
}
