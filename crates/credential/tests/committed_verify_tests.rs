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
#![cfg(feature = "native")]
//! Test coverage for this crate.

use std::collections::BTreeMap;

use reallyme_credential::committed::issue::{issue_credential, IssueInput, OsSaltRng};
use reallyme_credential::committed::model::{
    AssuranceLevel, CommitmentLimits, CredentialAlgorithm, CredentialKind, CredentialStatus,
    CredentialSubject, DomainTags, HolderBinding, KeyAssurance, KeyReference, PartyReference,
    PublicKeyRef, PublicKeyRepresentation, RawPublicKeySerialization, StatusPurpose,
};
use reallyme_credential::committed::verify::verify_credential;

use crypto_core::Algorithm as CryptoAlgorithm;
use crypto_dispatch::generate_keypair;
use reallyme_codec::{base64url::bytes_to_base64url, multikey::encode_multikey};
use reallyme_cose::{cose_key_from_public_bytes, cose_key_to_vec, Algorithm as CoseAlgorithm};

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

fn base_claims() -> BTreeMap<String, serde_json::Value> {
    let mut claims = BTreeMap::new();
    claims.insert("age".into(), serde_json::json!(42));
    claims.insert("name".into(), serde_json::json!("Alice"));
    claims
}

fn p256_input(issuer_public_key: Vec<u8>, holder_public_key: Vec<u8>) -> IssueInput {
    let mut input = base_input();
    input.issuer_verification_key = PublicKeyRef {
        alg: CredentialAlgorithm::P256,
        reference: KeyReference::DidVerificationMethod("did:test:issuer#key-1".into()),
        public_key: PublicKeyRepresentation::Raw {
            serialization: RawPublicKeySerialization::Sec1Compressed,
            bytes: issuer_public_key,
        },
        assurance: KeyAssurance::None,
    };
    input.subject.holder_binding = HolderBinding::CryptographicKey(PublicKeyRef {
        alg: CredentialAlgorithm::P256,
        reference: KeyReference::DidVerificationMethod("did:test:subject#key-1".into()),
        public_key: PublicKeyRepresentation::Raw {
            serialization: RawPublicKeySerialization::Sec1Compressed,
            bytes: holder_public_key,
        },
        assurance: KeyAssurance::None,
    });
    input
}

#[test]
fn verify_issued_credential_succeeds() {
    let (issuer_public, issuer_private) = generate_keypair(CryptoAlgorithm::Ed25519).unwrap();

    let mut rng = OsSaltRng;

    let issued = issue_credential(
        base_input(),
        &base_claims(),
        CryptoAlgorithm::Ed25519,
        &issuer_private,
        &mut rng,
    )
    .unwrap();

    let res = verify_credential(
        &issued.envelope,
        CryptoAlgorithm::Ed25519,
        &issuer_public,
        Some(&issued.subject_bundle),
    )
    .unwrap();

    assert_eq!(
        res.envelope_hash.len(),
        32,
        "envelope hash must be 32 bytes"
    );
}

#[test]
fn verify_issued_p256_credential_succeeds() {
    let (issuer_public, issuer_private) = generate_keypair(CryptoAlgorithm::P256).unwrap();
    let (holder_public, _holder_private) = generate_keypair(CryptoAlgorithm::P256).unwrap();
    let mut rng = OsSaltRng;

    let issued = issue_credential(
        p256_input(issuer_public.clone(), holder_public),
        &base_claims(),
        CryptoAlgorithm::P256,
        &issuer_private,
        &mut rng,
    )
    .unwrap();

    verify_credential(
        &issued.envelope,
        CryptoAlgorithm::P256,
        issuer_public.as_slice(),
        Some(&issued.subject_bundle),
    )
    .unwrap();
}

#[test]
fn issue_and_verify_support_all_declared_holder_key_representations() {
    let (issuer_public, issuer_private) = generate_keypair(CryptoAlgorithm::Ed25519).unwrap();
    let (holder_public, _holder_private) = generate_keypair(CryptoAlgorithm::Ed25519).unwrap();
    let encoded_holder = bytes_to_base64url(holder_public.as_slice());
    let holder_jwk = format!(
        "{{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"{encoded_holder}\",\"alg\":\"EdDSA\",\"use\":\"sig\",\"key_ops\":[\"verify\"]}}"
    )
    .into_bytes();
    let holder_cose = cose_key_from_public_bytes(CoseAlgorithm::Ed25519, holder_public.as_slice())
        .and_then(|key| cose_key_to_vec(&key))
        .unwrap();
    let holder_multikey = encode_multikey("ed25519-pub", holder_public.as_slice()).unwrap();

    let cases = [
        (
            KeyReference::DirectPublicKey,
            PublicKeyRepresentation::JwkJson(holder_jwk),
        ),
        (
            KeyReference::DirectPublicKey,
            PublicKeyRepresentation::CoseKey(holder_cose.to_vec()),
        ),
        (
            KeyReference::DidVerificationMethod("did:test:holder#authentication-1".into()),
            PublicKeyRepresentation::Multikey(holder_multikey),
        ),
    ];

    for (reference, representation) in cases {
        let mut input = base_input();
        input.subject = CredentialSubject {
            subject_reference: PartyReference::Absent,
            holder_binding: HolderBinding::CryptographicKey(PublicKeyRef {
                alg: CredentialAlgorithm::Ed25519,
                reference,
                public_key: representation,
                assurance: KeyAssurance::None,
            }),
        };
        let mut rng = OsSaltRng;
        let issued = issue_credential(
            input,
            &base_claims(),
            CryptoAlgorithm::Ed25519,
            issuer_private.as_slice(),
            &mut rng,
        )
        .unwrap();

        verify_credential(
            &issued.envelope,
            CryptoAlgorithm::Ed25519,
            issuer_public.as_slice(),
            Some(&issued.subject_bundle),
        )
        .unwrap();
        assert!(matches!(
            issued.envelope.subject.subject_reference,
            PartyReference::Absent
        ));
        assert!(issued.subject_bundle.holder_key.is_some());
    }
}

#[test]
fn issue_and_verify_keep_claims_and_bearer_binding_independent_from_subject_identity() {
    let (issuer_public, issuer_private) = generate_keypair(CryptoAlgorithm::Ed25519).unwrap();
    let bindings = [
        HolderBinding::ClaimsBased(vec!["name".into()]),
        HolderBinding::BearerWithoutBinding,
    ];

    for binding in bindings {
        let mut input = base_input();
        input.subject = CredentialSubject {
            subject_reference: PartyReference::Absent,
            holder_binding: binding,
        };
        let mut rng = OsSaltRng;
        let issued = issue_credential(
            input,
            &base_claims(),
            CryptoAlgorithm::Ed25519,
            issuer_private.as_slice(),
            &mut rng,
        )
        .unwrap();

        verify_credential(
            &issued.envelope,
            CryptoAlgorithm::Ed25519,
            issuer_public.as_slice(),
            Some(&issued.subject_bundle),
        )
        .unwrap();
        assert!(issued.subject_bundle.holder_key.is_none());
    }
}

#[test]
fn verify_fails_if_envelope_is_tampered() {
    let (issuer_public, issuer_private) = generate_keypair(CryptoAlgorithm::Ed25519).unwrap();

    let mut rng = OsSaltRng;

    let mut issued = issue_credential(
        base_input(),
        &base_claims(),
        CryptoAlgorithm::Ed25519,
        &issuer_private,
        &mut rng,
    )
    .unwrap();

    // Mutate envelope AFTER signing
    issued.envelope.valid_until += 1;

    let res = verify_credential(
        &issued.envelope,
        CryptoAlgorithm::Ed25519,
        &issuer_public,
        Some(&issued.subject_bundle),
    );

    assert!(
        res.is_err(),
        "verification must fail if envelope is modified"
    );
}

#[test]
fn verify_fails_if_signature_is_tampered() {
    let (issuer_public, issuer_private) = generate_keypair(CryptoAlgorithm::Ed25519).unwrap();

    let mut rng = OsSaltRng;

    let mut issued = issue_credential(
        base_input(),
        &base_claims(),
        CryptoAlgorithm::Ed25519,
        &issuer_private,
        &mut rng,
    )
    .unwrap();

    // Corrupt signature
    issued.envelope.issuer_signature.raw_rs[0] ^= 0xff;

    let res = verify_credential(
        &issued.envelope,
        CryptoAlgorithm::Ed25519,
        &issuer_public,
        Some(&issued.subject_bundle),
    );

    assert!(
        res.is_err(),
        "verification must fail if signature is corrupted"
    );
}

#[test]
fn verify_fails_if_merkle_opening_is_tampered() {
    let (issuer_public, issuer_private) = generate_keypair(CryptoAlgorithm::Ed25519).unwrap();

    let mut rng = OsSaltRng;

    let mut issued = issue_credential(
        base_input(),
        &base_claims(),
        CryptoAlgorithm::Ed25519,
        &issuer_private,
        &mut rng,
    )
    .unwrap();

    // Corrupt claim value in subject bundle
    issued.subject_bundle.claims[0].value[0] ^= 0xff;

    let res = verify_credential(
        &issued.envelope,
        CryptoAlgorithm::Ed25519,
        &issuer_public,
        Some(&issued.subject_bundle),
    );

    assert!(
        res.is_err(),
        "verification must fail if claim opening is tampered"
    );
}

#[test]
fn verify_rejects_inconsistent_or_unbounded_merkle_shapes() {
    let (issuer_public, issuer_private) = generate_keypair(CryptoAlgorithm::Ed25519).unwrap();
    let mut rng = OsSaltRng;
    let mut issued = issue_credential(
        base_input(),
        &base_claims(),
        CryptoAlgorithm::Ed25519,
        &issuer_private,
        &mut rng,
    )
    .unwrap();

    let original_count = issued.subject_bundle.tree.count;
    issued.subject_bundle.tree.count = 0;
    assert!(verify_credential(
        &issued.envelope,
        CryptoAlgorithm::Ed25519,
        &issuer_public,
        Some(&issued.subject_bundle),
    )
    .is_err());
    issued.subject_bundle.tree.count = original_count;

    let original_depth = issued.subject_bundle.tree.depth;
    issued.subject_bundle.tree.depth = original_depth.checked_add(1).unwrap();
    assert!(verify_credential(
        &issued.envelope,
        CryptoAlgorithm::Ed25519,
        &issuer_public,
        Some(&issued.subject_bundle),
    )
    .is_err());
    issued.subject_bundle.tree.depth = original_depth;

    let original_index = issued.subject_bundle.claims[0].index;
    issued.subject_bundle.claims[0].index = issued.subject_bundle.tree.count;
    assert!(verify_credential(
        &issued.envelope,
        CryptoAlgorithm::Ed25519,
        &issuer_public,
        Some(&issued.subject_bundle),
    )
    .is_err());
    issued.subject_bundle.claims[0].index = original_index;

    issued.subject_bundle.claims[0]
        .merkle_path
        .push(vec![0_u8; 32]);
    assert!(verify_credential(
        &issued.envelope,
        CryptoAlgorithm::Ed25519,
        &issuer_public,
        Some(&issued.subject_bundle),
    )
    .is_err());
}

#[test]
fn verify_without_subject_bundle_only_checks_issuer_signature() {
    let (issuer_public, issuer_private) = generate_keypair(CryptoAlgorithm::Ed25519).unwrap();

    let mut rng = OsSaltRng;

    let issued = issue_credential(
        base_input(),
        &base_claims(),
        CryptoAlgorithm::Ed25519,
        &issuer_private,
        &mut rng,
    )
    .unwrap();

    // No subject bundle provided
    let res = verify_credential(
        &issued.envelope,
        CryptoAlgorithm::Ed25519,
        &issuer_public,
        None,
    );

    assert!(
        res.is_ok(),
        "issuer-only verification should succeed without bundle"
    );
}
