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

use std::collections::BTreeMap;

use reallyme_credential::committed::canonical::canonical_credential_bytes;
use reallyme_credential::committed::issue::{issue_credential, IssueInput, OsSaltRng};
use reallyme_credential::committed::model::{
    AssuranceLevel, CommitmentLimits, CredentialAlgorithm, CredentialKind, CredentialStatus,
    CredentialSubject, DomainTags, HolderBinding, KeyAssurance, KeyReference, PartyReference,
    PublicKeyRef, PublicKeyRepresentation, RawPublicKeySerialization, StatusPurpose,
};
use reallyme_credential::committed::proof_binding::validate_credential_proof_binding;

use crypto_core::Algorithm as CryptoAlgorithm;
use crypto_dispatch::{generate_keypair, verify};
use zeroize::Zeroize;

fn base_input() -> IssueInput {
    IssueInput {
        kind: CredentialKind::Pid,
        profile_id: "claims-v1".into(),
        assurance: AssuranceLevel::Substantial,

        issuer_reference: PartyReference::Did("did:test:issuer".into()),
        issuer_verification_key: ed25519_key("did:test:issuer#key-1", 2),
        issuer_country: "EU".into(),

        valid_from: 1_700_000_000,
        valid_until: 1_800_000_000,

        status: CredentialStatus {
            status_list_url: "https://example.com/status".into(),
            status_list_id: [0u8; 32],
            status_list_index: 0,
            purpose: StatusPurpose::Revocation,
        },

        subject: CredentialSubject {
            subject_reference: PartyReference::Did("did:test:subject".into()),
            holder_binding: HolderBinding::CryptographicKey(ed25519_key(
                "did:test:subject#key-1",
                1,
            )),
        },

        claimset_id: "claims-v1".into(),
        domain_tags: DomainTags {
            clm: "CLM1".into(),
            leaf: "LEAF1".into(),
            node: "NODE1".into(),
        },
        limits: CommitmentLimits {
            max_value_len: 64,
            salt_len: 16,
        },

        qeaa_compliance: None,
    }
}

fn ed25519_key(did_url: &str, marker: u8) -> PublicKeyRef {
    PublicKeyRef {
        alg: CredentialAlgorithm::Ed25519,
        reference: KeyReference::DidVerificationMethod(did_url.into()),
        public_key: PublicKeyRepresentation::Raw {
            serialization: RawPublicKeySerialization::FixedWidth,
            bytes: vec![marker; 32],
        },
        assurance: KeyAssurance::None,
    }
}

fn p256_key(did_url: &str, bytes: Vec<u8>) -> PublicKeyRef {
    PublicKeyRef {
        alg: CredentialAlgorithm::P256,
        reference: KeyReference::DidVerificationMethod(did_url.into()),
        public_key: PublicKeyRepresentation::Raw {
            serialization: RawPublicKeySerialization::Sec1Compressed,
            bytes,
        },
        assurance: KeyAssurance::None,
    }
}

fn p256_input(issuer_public_key: Vec<u8>, holder_public_key: Vec<u8>) -> IssueInput {
    let mut input = base_input();
    input.issuer_verification_key = p256_key("did:test:issuer#key-1", issuer_public_key);
    input.subject.holder_binding =
        HolderBinding::CryptographicKey(p256_key("did:test:subject#key-1", holder_public_key));
    input
}

#[test]
fn issue_basic_credential_with_real_keys() {
    // 🔐 Generate a REAL Ed25519 keypair
    let (issuer_public, issuer_private) = generate_keypair(CryptoAlgorithm::Ed25519).unwrap();

    let mut rng = OsSaltRng;

    let mut claims = BTreeMap::new();
    claims.insert("age".into(), serde_json::json!(42));
    claims.insert("name".into(), serde_json::json!("Alice"));

    let input = base_input();

    let res = issue_credential(
        input,
        &claims,
        CryptoAlgorithm::Ed25519,
        &issuer_private,
        &mut rng,
    )
    .unwrap();

    // Canonical bytes must be deterministic
    let canon = canonical_credential_bytes(&res.envelope).unwrap();
    assert!(!canon.is_empty());

    // 🔒 Verify issuer signature against canonical envelope
    verify(
        CryptoAlgorithm::Ed25519,
        &issuer_public,
        &canon,
        &res.envelope.issuer_signature.raw_rs,
    )
    .unwrap();

    // Merkle root present
    assert_eq!(res.envelope.claims_commitment.merkle_root.len(), 32);

    // Subject bundle has openings
    assert_eq!(res.subject_bundle.claims.len(), 2);
    assert!(res.proof_binding.is_none());
}

#[test]
fn p256_issuance_emits_and_validates_atomic_proof_binding() {
    let (issuer_public, issuer_private) = generate_keypair(CryptoAlgorithm::P256).unwrap();
    let (holder_public, _holder_private) = generate_keypair(CryptoAlgorithm::P256).unwrap();
    let mut rng = OsSaltRng;
    let mut claims = BTreeMap::new();
    claims.insert("age".into(), serde_json::json!(42));

    let result = issue_credential(
        p256_input(issuer_public, holder_public),
        &claims,
        CryptoAlgorithm::P256,
        &issuer_private,
        &mut rng,
    )
    .unwrap();
    let binding = result.proof_binding.as_ref().unwrap();

    validate_credential_proof_binding(&result.envelope, &result.subject_bundle, binding).unwrap();
    assert_eq!(binding.version, 1);
    assert_ne!(binding.issuance_binding, [0_u8; 32]);
    assert_ne!(
        binding
            .credential_binding([1_u8; 32], [2_u8; 32], 1_800_000_000)
            .unwrap(),
        binding
            .credential_binding([3_u8; 32], [2_u8; 32], 1_800_000_000)
            .unwrap()
    );
    assert!(!format!("{binding:?}").contains("102"));
}

#[test]
fn proof_binding_rejects_cross_credential_transplantation() {
    let (issuer_public, issuer_private) = generate_keypair(CryptoAlgorithm::P256).unwrap();
    let (holder_a_public, _holder_a_private) = generate_keypair(CryptoAlgorithm::P256).unwrap();
    let (holder_b_public, _holder_b_private) = generate_keypair(CryptoAlgorithm::P256).unwrap();
    let mut claims_a = BTreeMap::new();
    claims_a.insert("age".into(), serde_json::json!(42));
    let mut claims_b = BTreeMap::new();
    claims_b.insert("age".into(), serde_json::json!(43));
    let mut rng_a = OsSaltRng;
    let mut rng_b = OsSaltRng;

    let first = issue_credential(
        p256_input(issuer_public.clone(), holder_a_public),
        &claims_a,
        CryptoAlgorithm::P256,
        &issuer_private,
        &mut rng_a,
    )
    .unwrap();
    let second = issue_credential(
        p256_input(issuer_public, holder_b_public),
        &claims_b,
        CryptoAlgorithm::P256,
        &issuer_private,
        &mut rng_b,
    )
    .unwrap();

    assert!(validate_credential_proof_binding(
        &second.envelope,
        &second.subject_bundle,
        first.proof_binding.as_ref().unwrap(),
    )
    .is_err());
}

#[test]
fn proof_binding_rejects_tampered_root_subject_and_signatures() {
    let (issuer_public, issuer_private) = generate_keypair(CryptoAlgorithm::P256).unwrap();
    let (holder_public, _holder_private) = generate_keypair(CryptoAlgorithm::P256).unwrap();
    let mut rng = OsSaltRng;
    let mut claims = BTreeMap::new();
    claims.insert("age".into(), serde_json::json!(42));
    let result = issue_credential(
        p256_input(issuer_public, holder_public),
        &claims,
        CryptoAlgorithm::P256,
        &issuer_private,
        &mut rng,
    )
    .unwrap();

    let mut wrong_root = result.proof_binding.as_ref().unwrap().clone();
    wrong_root.claims_root[0] ^= 1;
    assert!(validate_credential_proof_binding(
        &result.envelope,
        &result.subject_bundle,
        &wrong_root,
    )
    .is_err());

    let mut wrong_subject = result.proof_binding.as_ref().unwrap().clone();
    wrong_subject.subject_public_key_x[0] ^= 1;
    assert!(validate_credential_proof_binding(
        &result.envelope,
        &result.subject_bundle,
        &wrong_subject,
    )
    .is_err());

    let mut wrong_signature = result.proof_binding.as_ref().unwrap().clone();
    wrong_signature.issuer_root_binding_signature[0] ^= 1;
    assert!(validate_credential_proof_binding(
        &result.envelope,
        &result.subject_bundle,
        &wrong_signature,
    )
    .is_err());
}

#[test]
fn issued_credential_fails_verification_if_tampered() {
    let (issuer_public, issuer_private) = generate_keypair(CryptoAlgorithm::Ed25519).unwrap();

    let mut rng = OsSaltRng;

    let mut claims = BTreeMap::new();
    claims.insert("email".into(), serde_json::json!("alice@example.com"));

    let mut res = issue_credential(
        base_input(),
        &claims,
        CryptoAlgorithm::Ed25519,
        &issuer_private,
        &mut rng,
    )
    .unwrap();

    // Mutate credential AFTER signing
    res.envelope.valid_until += 1;

    let canon = canonical_credential_bytes(&res.envelope).unwrap();

    assert!(
        verify(
            CryptoAlgorithm::Ed25519,
            &issuer_public,
            &canon,
            &res.envelope.issuer_signature.raw_rs,
        )
        .is_err(),
        "signature verification must fail if envelope is modified"
    );
}

#[test]
fn issued_credential_debug_is_privacy_safe_and_owned_material_can_be_zeroized() {
    let (_issuer_public, issuer_private) = generate_keypair(CryptoAlgorithm::Ed25519).unwrap();

    let mut rng = OsSaltRng;

    let mut claims = BTreeMap::new();
    claims.insert("email".into(), serde_json::json!("alice@example.com"));

    let mut res = issue_credential(
        base_input(),
        &claims,
        CryptoAlgorithm::Ed25519,
        &issuer_private,
        &mut rng,
    )
    .unwrap();

    let envelope_debug = format!("{:?}", res.envelope);
    let bundle_debug = format!("{:?}", res.subject_bundle);
    assert!(!envelope_debug.contains("did:test:issuer"));
    assert!(!envelope_debug.contains("did:test:subject"));
    assert!(!envelope_debug.contains("https://example.com/status"));
    assert!(!bundle_debug.contains("alice@example.com"));

    res.envelope.zeroize();
    res.subject_bundle.zeroize();

    assert!(matches!(
        &res.envelope.issuer_reference,
        PartyReference::Did(value) if value.is_empty()
    ));
    assert!(matches!(
        &res.envelope.subject.subject_reference,
        PartyReference::Did(value) if value.is_empty()
    ));
    assert!(res.envelope.status.status_list_url.is_empty());
    assert!(res.envelope.issuer_signature.raw_rs.is_empty());
    assert!(res.subject_bundle.holder_key.is_none());
    assert!(res.subject_bundle.envelope_hash.is_empty());
    assert!(res.subject_bundle.issuer_signature.raw_rs.is_empty());
    assert!(res.subject_bundle.claims.is_empty());
}

#[test]
fn issuance_rejects_empty_validity_window() {
    let (_issuer_public, issuer_private) = generate_keypair(CryptoAlgorithm::Ed25519).unwrap();
    let mut claims = BTreeMap::new();
    claims.insert("age".into(), serde_json::json!(42));
    let mut input = base_input();
    input.valid_until = input.valid_from;

    let result = issue_credential(
        input,
        &claims,
        CryptoAlgorithm::Ed25519,
        &issuer_private,
        &mut OsSaltRng,
    );

    assert!(matches!(
        result,
        Err(reallyme_credential::committed::error::VcError::InvalidCredential)
    ));
}

#[test]
fn issuance_builds_verifiable_trees_for_non_power_of_two_claim_counts() {
    for claim_count in [1_usize, 3, 5, 6, 7] {
        let (_issuer_public, issuer_private) = generate_keypair(CryptoAlgorithm::Ed25519).unwrap();
        let mut claims = BTreeMap::new();
        for index in 0..claim_count {
            claims.insert(format!("claim{index}"), serde_json::json!(index));
        }

        let issued = issue_credential(
            base_input(),
            &claims,
            CryptoAlgorithm::Ed25519,
            &issuer_private,
            &mut OsSaltRng,
        )
        .unwrap();

        assert_eq!(issued.subject_bundle.claims.len(), claim_count);
        reallyme_credential::committed::verify::verify_merkle_only(
            &issued.envelope,
            &issued.subject_bundle,
        )
        .unwrap();
    }
}
