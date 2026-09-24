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
//! Tests for JWT VC envelope helpers.

use std::collections::BTreeMap;

use identity_vc_jwt::{decode_verify_vc_jwt, encode_vc_jwt};
use reallyme_credential::committed::issue::{issue_credential, IssueInput, OsSaltRng};
use reallyme_credential::committed::model::{
    AssuranceLevel, CommitmentLimits, CredentialAlgorithm, CredentialKind, CredentialStatus,
    CredentialSubject, DomainTags, HolderBinding, KeyAssurance, KeyReference, PartyReference,
    PublicKeyRef, PublicKeyRepresentation, RawPublicKeySerialization, StatusPurpose,
};
use reallyme_credential::committed::signed_envelope::decode_signed_envelope_cbor;

use codec_base64url::bytes_to_base64url;
use crypto_core::Algorithm as CryptoAlgorithm;
use crypto_dispatch::{generate_keypair, verify};
use envelopes_jwk::{Jwk, OkpJwk};

fn base_input() -> IssueInput {
    IssueInput {
        kind: CredentialKind::Pid,
        profile_id: "claims-v1".into(),
        assurance: AssuranceLevel::Substantial,
        issuer_reference: PartyReference::Did("did:test:issuer".into()),
        issuer_verification_key: ed25519_key("did:test:issuer#key-1", vec![2; 32]),
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

#[test]
fn vc_jwt_carries_signed_envelope_and_verifies() {
    let (issuer_pub, issuer_priv) = generate_keypair(CryptoAlgorithm::Ed25519).unwrap();

    // Minimal issuer JWK (must match the envelopes-jwk shape)
    // Use a JWK builder when available; otherwise adapt to local JWK constructors.
    let issuer_jwk = Jwk::Okp(OkpJwk {
        kty: "OKP".into(),
        crv: "Ed25519".into(),
        x: bytes_to_base64url(&issuer_pub),
        alg: Some("EdDSA".into()),
        kid: Some("kid-1".into()),
        use_: None,
    });

    let mut rng = OsSaltRng;

    let mut claims = BTreeMap::new();
    claims.insert("email".into(), serde_json::json!("alice@example.com"));

    let issued = issue_credential(
        base_input(),
        &claims,
        CryptoAlgorithm::Ed25519,
        &issuer_priv,
        &mut rng,
    )
    .unwrap();

    let jwt = encode_vc_jwt(
        &issued.envelope,
        "did:test:issuer",
        "did:test:subject",
        &issuer_jwk,
        &issuer_priv,
        None,
    )
    .unwrap();

    let (_payload, se_bytes) = decode_verify_vc_jwt(&jwt, &issuer_jwk, &issuer_pub).unwrap();

    // Verify the signed envelope wrapper too
    let (canon, sig) = decode_signed_envelope_cbor(&se_bytes).unwrap();

    verify(CryptoAlgorithm::Ed25519, &issuer_pub, &canon, &sig.raw_rs).unwrap();
}
