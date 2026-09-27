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
    const P256_GENERATOR: [u8; 65] = [
        0x04, 0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4,
        0x40, 0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8,
        0x98, 0xc2, 0x96, 0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb, 0x4a,
        0x7c, 0x0f, 0x9e, 0x16, 0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce, 0xcb, 0xb6, 0x40,
        0x68, 0x37, 0xbf, 0x51, 0xf5,
    ];
    const P256_GENERATOR_TIMES_TWO: [u8; 65] = [
        0x04, 0x7c, 0xf2, 0x7b, 0x18, 0x8d, 0x03, 0x4f, 0x7e, 0x8a, 0x52, 0x38, 0x03, 0x04, 0xb5,
        0x1a, 0xc3, 0xc0, 0x89, 0x69, 0xe2, 0x77, 0xf2, 0x1b, 0x35, 0xa6, 0x0b, 0x48, 0xfc, 0x47,
        0x66, 0x99, 0x78, 0x07, 0x77, 0x55, 0x10, 0xdb, 0x8e, 0xd0, 0x40, 0x29, 0x3d, 0x9a, 0xc6,
        0x9f, 0x74, 0x30, 0xdb, 0xba, 0x7d, 0xad, 0xe6, 0x3c, 0xe9, 0x82, 0x29, 0x9e, 0x04, 0xb7,
        0x9d, 0x22, 0x78, 0x73, 0xd1,
    ];
    let bytes = match marker {
        1 => P256_GENERATOR,
        _ => P256_GENERATOR_TIMES_TWO,
    };
    PublicKeyRef {
        alg: CredentialAlgorithm::P256,
        reference: KeyReference::DidVerificationMethod(did_url.into()),
        public_key: PublicKeyRepresentation::Raw {
            serialization: RawPublicKeySerialization::Sec1Uncompressed,
            bytes: bytes.to_vec(),
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
            cert_fingerprint_sha256: [
                0x3a, 0xdd, 0xe0, 0x1b, 0x2d, 0xe5, 0x4e, 0x88, 0x79, 0x40, 0x48, 0xd5, 0x51, 0xbb,
                0x98, 0x6b, 0xc1, 0xb2, 0xb8, 0x5d, 0xd0, 0x10, 0x1e, 0x80, 0x81, 0xe7, 0x09, 0xc4,
                0xa6, 0xab, 0x57, 0xed,
            ],
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
