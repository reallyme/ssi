// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(
    missing_docs,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::print_stderr
)]
//! Test coverage for this crate.

use std::collections::BTreeMap;

use crypto_core::Algorithm;
use crypto_dispatch::generate_keypair;

use identity_credential_vc_api::{
    validate_credential, verify_credential_merkle_root, verify_credential_signature,
};

use reallyme_credential::committed::{
    issue::{issue_credential, IssueInput, OsSaltRng},
    model::{
        AssuranceLevel, CommitmentLimits, CredentialAlgorithm, CredentialKind, CredentialStatus,
        CredentialSubject, DomainTags, HolderBinding, KeyAssurance, KeyReference, PartyReference,
        PublicKeyRef, PublicKeyRepresentation, RawPublicKeySerialization, StatusPurpose,
    },
};

fn base_input() -> IssueInput {
    IssueInput {
        kind: CredentialKind::Pid,
        profile_id: "claims-v1".into(),
        assurance: AssuranceLevel::Substantial,

        issuer_reference: PartyReference::Did("did:test:issuer".into()),
        issuer_verification_key: ed25519_key("did:test:issuer#key-1", vec![7; 32]),
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
                vec![1; 32],
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

fn base_claims() -> BTreeMap<String, serde_json::Value> {
    let mut claims = BTreeMap::new();
    claims.insert("age".into(), serde_json::json!(42));
    claims.insert("name".into(), serde_json::json!("Alice"));
    claims
}

#[test]
fn api_validates_full_credential() {
    let (pk, sk) = generate_keypair(Algorithm::Ed25519).unwrap();
    let mut rng = OsSaltRng;

    let issued = issue_credential(
        base_input(),
        &base_claims(),
        Algorithm::Ed25519,
        &sk,
        &mut rng,
    )
    .unwrap();

    validate_credential(
        &issued.envelope,
        Algorithm::Ed25519,
        &pk,
        Some(&issued.subject_bundle),
    )
    .expect("full credential validation should succeed");
}

#[test]
fn api_verifies_signature_only() {
    let (pk, sk) = generate_keypair(Algorithm::Ed25519).unwrap();
    let mut rng = OsSaltRng;

    let issued = issue_credential(
        base_input(),
        &base_claims(),
        Algorithm::Ed25519,
        &sk,
        &mut rng,
    )
    .unwrap();

    verify_credential_signature(&issued.envelope, Algorithm::Ed25519, &pk)
        .expect("signature verification should succeed");
}

#[test]
fn api_verifies_merkle_only() {
    let (_pk, sk) = generate_keypair(Algorithm::Ed25519).unwrap();
    let mut rng = OsSaltRng;

    let issued = issue_credential(
        base_input(),
        &base_claims(),
        Algorithm::Ed25519,
        &sk,
        &mut rng,
    )
    .unwrap();

    // Merkle verification ignores issuer signature
    verify_credential_merkle_root(&issued.envelope, &issued.subject_bundle)
        .expect("merkle verification should succeed");
}

#[test]
fn api_signature_only_succeeds_without_bundle() {
    let (pk, sk) = generate_keypair(Algorithm::Ed25519).unwrap();
    let mut rng = OsSaltRng;

    let issued = issue_credential(
        base_input(),
        &base_claims(),
        Algorithm::Ed25519,
        &sk,
        &mut rng,
    )
    .unwrap();

    verify_credential_signature(&issued.envelope, Algorithm::Ed25519, &pk)
        .expect("signature-only verification must succeed without bundle");
}
