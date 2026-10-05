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
use reallyme_credential::committed::error::VcError;
use reallyme_credential::committed::issue::{
    issue_credential, issue_credential_with_payload_signer, IssueInput, OsSaltRng,
};
use reallyme_credential::committed::model::{
    AssuranceLevel, CommitmentLimits, CredentialAlgorithm, CredentialKind, CredentialStatus,
    CredentialSubject, DomainTags, HolderBinding, KeyAssurance, KeyReference, PartyReference,
    PublicKeyRef, PublicKeyRepresentation, RawPublicKeySerialization, StatusPurpose,
};
use reallyme_credential::committed::proof_binding::{
    issue_credential_proof_binding, validate_credential_proof_binding,
};
use reallyme_credential::DispatchCredentialIssuerSigner;

use crypto_core::Algorithm as CryptoAlgorithm;
use crypto_dispatch::{generate_keypair, verify};
use zeroize::Zeroize;

#[path = "committed_issue_tests/p256_high_s.rs"]
mod p256_high_s;
use p256_high_s::{assert_low_s, high_s_twin, HighSP256IssuerSigner};

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
    ed25519_key_bytes(did_url, vec![marker; 32])
}

fn ed25519_key_bytes(did_url: &str, bytes: Vec<u8>) -> PublicKeyRef {
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
        p256_input(issuer_public.clone(), holder_public),
        &claims,
        CryptoAlgorithm::P256,
        &issuer_private,
        &mut rng,
    )
    .unwrap();
    let binding = result.proof_binding.as_ref().unwrap();

    validate_credential_proof_binding(
        &result.envelope,
        &result.subject_bundle,
        binding,
        &issuer_public,
    )
    .unwrap();
    assert_eq!(binding.version, 1);
    assert_ne!(binding.issuance_binding, [0_u8; 32]);
    assert_ne!(
        binding
            .credential_binding([1_u8; 32], [2_u8; 32], [4_u8; 32], 1_800_000_000)
            .unwrap(),
        binding
            .credential_binding([3_u8; 32], [2_u8; 32], [4_u8; 32], 1_800_000_000)
            .unwrap()
    );
    assert_ne!(
        binding
            .credential_binding([1_u8; 32], [2_u8; 32], [4_u8; 32], 1_800_000_000)
            .unwrap(),
        binding
            .credential_binding([1_u8; 32], [2_u8; 32], [5_u8; 32], 1_800_000_000)
            .unwrap()
    );
    assert!(!format!("{binding:?}").contains("102"));
}

#[test]
fn proof_binding_can_be_issued_for_an_existing_signed_envelope() {
    let (issuer_public, issuer_private) = generate_keypair(CryptoAlgorithm::P256).unwrap();
    let (holder_public, _holder_private) = generate_keypair(CryptoAlgorithm::P256).unwrap();
    let mut claims = BTreeMap::new();
    claims.insert("age".into(), serde_json::json!(42));
    let result = issue_credential(
        p256_input(issuer_public.clone(), holder_public),
        &claims,
        CryptoAlgorithm::P256,
        &issuer_private,
        &mut OsSaltRng,
    )
    .unwrap();
    let signer = DispatchCredentialIssuerSigner {
        private_key: &issuer_private,
        verification_key: &result.envelope.issuer_signature.verification_key,
    };
    let binding = issue_credential_proof_binding(&result.envelope, &signer).unwrap();
    validate_credential_proof_binding(
        &result.envelope,
        &result.subject_bundle,
        &binding,
        &issuer_public,
    )
    .unwrap();
    assert_eq!(
        binding.issuance_binding,
        result.proof_binding.as_ref().unwrap().issuance_binding
    );

    let (other_public, other_private) = generate_keypair(CryptoAlgorithm::P256).unwrap();
    let other_key = p256_key("did:test:issuer#key-2", other_public);
    let wrong_signer = DispatchCredentialIssuerSigner {
        private_key: &issuer_private,
        verification_key: &other_key,
    };
    assert_eq!(
        issue_credential_proof_binding(&result.envelope, &wrong_signer),
        Err(VcError::ProofBindingTrustedIssuerMismatch)
    );

    let mismatched_private_key = DispatchCredentialIssuerSigner {
        private_key: &other_private,
        verification_key: &result.envelope.issuer_signature.verification_key,
    };
    assert_eq!(
        issue_credential_proof_binding(&result.envelope, &mismatched_private_key),
        Err(VcError::ProofBindingSignatureInvalid)
    );
}

#[test]
fn proof_binding_canonicalizes_high_s_signer_output_and_rejects_high_s_artifacts() {
    let (issuer_public, issuer_private) = generate_keypair(CryptoAlgorithm::P256).unwrap();
    let (holder_public, _holder_private) = generate_keypair(CryptoAlgorithm::P256).unwrap();
    let mut claims = BTreeMap::new();
    claims.insert("age".into(), serde_json::json!(42));
    let input = p256_input(issuer_public.clone(), holder_public);
    let verification_key = input.issuer_verification_key.clone();
    let signer = HighSP256IssuerSigner {
        private_key: &issuer_private,
        verification_key: &verification_key,
    };
    let result =
        issue_credential_with_payload_signer(input, &claims, &signer, &mut OsSaltRng).unwrap();
    let binding = issue_credential_proof_binding(&result.envelope, &signer).unwrap();
    let envelope_signature: [u8; 64] = result
        .envelope
        .issuer_signature
        .raw_rs
        .as_slice()
        .try_into()
        .unwrap();

    assert_low_s(&envelope_signature);
    assert_low_s(
        &result
            .proof_binding
            .as_ref()
            .unwrap()
            .issuer_envelope_signature,
    );
    assert_low_s(
        &result
            .proof_binding
            .as_ref()
            .unwrap()
            .issuer_root_binding_signature,
    );
    assert_low_s(
        &result
            .proof_binding
            .as_ref()
            .unwrap()
            .issuer_subject_binding_signature,
    );
    assert_low_s(
        &result
            .proof_binding
            .as_ref()
            .unwrap()
            .issuer_validity_status_signature,
    );
    assert_low_s(&binding.issuer_envelope_signature);
    assert_low_s(&binding.issuer_root_binding_signature);
    assert_low_s(&binding.issuer_subject_binding_signature);
    assert_low_s(&binding.issuer_validity_status_signature);
    validate_credential_proof_binding(
        &result.envelope,
        &result.subject_bundle,
        &binding,
        &issuer_public,
    )
    .unwrap();

    let mut high_s_root = binding.clone();
    high_s_root.issuer_root_binding_signature = high_s_twin(binding.issuer_root_binding_signature);
    assert_eq!(
        validate_credential_proof_binding(
            &result.envelope,
            &result.subject_bundle,
            &high_s_root,
            &issuer_public,
        ),
        Err(VcError::ProofBindingSignatureInvalid)
    );

    let mut high_s_subject = binding.clone();
    high_s_subject.issuer_subject_binding_signature =
        high_s_twin(binding.issuer_subject_binding_signature);
    assert_eq!(
        validate_credential_proof_binding(
            &result.envelope,
            &result.subject_bundle,
            &high_s_subject,
            &issuer_public,
        ),
        Err(VcError::ProofBindingSignatureInvalid)
    );

    let mut high_s_validity_status = binding.clone();
    high_s_validity_status.issuer_validity_status_signature =
        high_s_twin(binding.issuer_validity_status_signature);
    assert_eq!(
        validate_credential_proof_binding(
            &result.envelope,
            &result.subject_bundle,
            &high_s_validity_status,
            &issuer_public,
        ),
        Err(VcError::ProofBindingSignatureInvalid)
    );

    // The general committed-credential verifier follows interoperable ES256;
    // only the proof-bound profile requires a unique low-S representation.
    let canonical_hash = reallyme_credential::committed::verify::verify_credential(
        &result.envelope,
        CryptoAlgorithm::P256,
        &issuer_public,
        None,
    )
    .unwrap()
    .envelope_hash;
    let mut high_s_envelope = result.envelope;
    high_s_envelope.issuer_signature.raw_rs = high_s_twin(envelope_signature).to_vec();
    assert_eq!(
        reallyme_credential::committed::verify::verify_credential(
            &high_s_envelope,
            CryptoAlgorithm::P256,
            &issuer_public,
            None,
        )
        .unwrap()
        .envelope_hash,
        canonical_hash
    );
    assert_eq!(
        validate_credential_proof_binding(
            &high_s_envelope,
            &result.subject_bundle,
            &binding,
            &issuer_public,
        ),
        Err(VcError::ProofBindingSignatureInvalid)
    );

    let mut high_s_binding = binding.clone();
    high_s_binding.issuer_envelope_signature = high_s_twin(binding.issuer_envelope_signature);
    high_s_binding.issuer_root_binding_signature =
        high_s_twin(binding.issuer_root_binding_signature);
    high_s_binding.issuer_subject_binding_signature =
        high_s_twin(binding.issuer_subject_binding_signature);
    high_s_binding.issuer_validity_status_signature =
        high_s_twin(binding.issuer_validity_status_signature);
    high_s_envelope.issuer_signature.raw_rs = high_s_binding.issuer_envelope_signature.to_vec();

    assert_eq!(
        issue_credential_proof_binding(&high_s_envelope, &signer),
        Err(VcError::ProofBindingSignatureInvalid)
    );
    assert_eq!(
        validate_credential_proof_binding(
            &high_s_envelope,
            &result.subject_bundle,
            &high_s_binding,
            &issuer_public,
        ),
        Err(VcError::ProofBindingSignatureInvalid)
    );
}

#[test]
fn p256_issuance_rejects_signatures_from_a_different_key() {
    let (issuer_public, _issuer_private) = generate_keypair(CryptoAlgorithm::P256).unwrap();
    let (_other_public, other_private) = generate_keypair(CryptoAlgorithm::P256).unwrap();
    let (holder_public, _holder_private) = generate_keypair(CryptoAlgorithm::P256).unwrap();
    let input = p256_input(issuer_public, holder_public);
    let verification_key = input.issuer_verification_key.clone();
    let signer = HighSP256IssuerSigner {
        private_key: &other_private,
        verification_key: &verification_key,
    };
    let mut claims = BTreeMap::new();
    claims.insert("age".into(), serde_json::json!(42));

    assert!(matches!(
        issue_credential_with_payload_signer(input, &claims, &signer, &mut OsSaltRng),
        Err(VcError::ProofBindingSignatureInvalid)
    ));
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
        p256_input(issuer_public.clone(), holder_b_public),
        &claims_b,
        CryptoAlgorithm::P256,
        &issuer_private,
        &mut rng_b,
    )
    .unwrap();

    assert_eq!(
        validate_credential_proof_binding(
            &second.envelope,
            &second.subject_bundle,
            first.proof_binding.as_ref().unwrap(),
            &issuer_public,
        ),
        Err(VcError::ProofBindingMismatch)
    );
}

#[test]
fn proof_binding_rejects_an_attacker_controlled_embedded_issuer_key() {
    let (trusted_issuer_public, _trusted_issuer_private) =
        generate_keypair(CryptoAlgorithm::P256).unwrap();
    let (attacker_public, attacker_private) = generate_keypair(CryptoAlgorithm::P256).unwrap();
    let (holder_public, _holder_private) = generate_keypair(CryptoAlgorithm::P256).unwrap();
    let mut claims = BTreeMap::new();
    claims.insert("age".into(), serde_json::json!(42));
    let mut rng = OsSaltRng;

    let forged = issue_credential(
        p256_input(attacker_public, holder_public),
        &claims,
        CryptoAlgorithm::P256,
        &attacker_private,
        &mut rng,
    )
    .unwrap();

    assert!(matches!(
        validate_credential_proof_binding(
            &forged.envelope,
            &forged.subject_bundle,
            forged.proof_binding.as_ref().unwrap(),
            &trusted_issuer_public,
        ),
        Err(VcError::ProofBindingTrustedIssuerMismatch)
    ));
}

#[test]
fn proof_binding_rejects_tampered_root_subject_and_signatures() {
    let (issuer_public, issuer_private) = generate_keypair(CryptoAlgorithm::P256).unwrap();
    let (holder_public, _holder_private) = generate_keypair(CryptoAlgorithm::P256).unwrap();
    let mut rng = OsSaltRng;
    let mut claims = BTreeMap::new();
    claims.insert("age".into(), serde_json::json!(42));
    let result = issue_credential(
        p256_input(issuer_public.clone(), holder_public),
        &claims,
        CryptoAlgorithm::P256,
        &issuer_private,
        &mut rng,
    )
    .unwrap();

    let mut wrong_root = result.proof_binding.as_ref().unwrap().clone();
    wrong_root.claims_root[0] ^= 1;
    assert_eq!(
        validate_credential_proof_binding(
            &result.envelope,
            &result.subject_bundle,
            &wrong_root,
            &issuer_public,
        ),
        Err(VcError::ProofBindingMismatch)
    );

    let mut wrong_subject = result.proof_binding.as_ref().unwrap().clone();
    wrong_subject.subject_public_key_x[0] ^= 1;
    assert_eq!(
        validate_credential_proof_binding(
            &result.envelope,
            &result.subject_bundle,
            &wrong_subject,
            &issuer_public,
        ),
        Err(VcError::ProofBindingMismatch)
    );

    let mut wrong_signature = result.proof_binding.as_ref().unwrap().clone();
    wrong_signature.issuer_root_binding_signature[0] ^= 1;
    assert_eq!(
        validate_credential_proof_binding(
            &result.envelope,
            &result.subject_bundle,
            &wrong_signature,
            &issuer_public,
        ),
        Err(VcError::ProofBindingSignatureInvalid)
    );

    let mut wrong_validity_status_signature = result.proof_binding.as_ref().unwrap().clone();
    wrong_validity_status_signature.issuer_validity_status_signature[0] ^= 1;
    assert_eq!(
        validate_credential_proof_binding(
            &result.envelope,
            &result.subject_bundle,
            &wrong_validity_status_signature,
            &issuer_public,
        ),
        Err(VcError::ProofBindingSignatureInvalid)
    );
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
        let (issuer_public, issuer_private) = generate_keypair(CryptoAlgorithm::Ed25519).unwrap();
        let mut claims = BTreeMap::new();
        for index in 0..claim_count {
            claims.insert(format!("claim{index}"), serde_json::json!(index));
        }

        let mut input = base_input();
        input.issuer_verification_key =
            ed25519_key_bytes("did:test:issuer#key-1", issuer_public.clone());
        let issued = issue_credential(
            input,
            &claims,
            CryptoAlgorithm::Ed25519,
            &issuer_private,
            &mut OsSaltRng,
        )
        .unwrap();

        assert_eq!(issued.subject_bundle.claims.len(), claim_count);
        reallyme_credential::committed::verify::verify_credential(
            &issued.envelope,
            CryptoAlgorithm::Ed25519,
            &issuer_public,
            Some(&issued.subject_bundle),
        )
        .unwrap();
    }
}
