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

use reallyme_credential::committed::issue::{issue_credential, IssueInput, OsSaltRng};
use reallyme_credential::committed::model::{
    AssuranceLevel, CommitmentLimits, CredentialAlgorithm, CredentialKind, CredentialStatus,
    CredentialSubject, DomainTags, HolderBinding, KeyAssurance, KeyReference, PartyReference,
    PublicKeyRef, PublicKeyRepresentation, RawPublicKeySerialization, StatusPurpose,
};
use reallyme_credential::committed::signed_envelope::{
    decode_signed_envelope_cbor, encode_signed_envelope_cbor,
};

use codec_cbor::{encode_dag_cbor, CborValue};
use crypto_core::Algorithm as CryptoAlgorithm;
use crypto_dispatch::{generate_keypair, verify};

const OVERSIZED_SIGNED_ENVELOPE_BYTES: usize = (1024 * 1024) + 1;

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

#[test]
fn signed_envelope_roundtrip_and_verifies() {
    let (pubk, privk) = generate_keypair(CryptoAlgorithm::Ed25519).unwrap();

    let mut rng = OsSaltRng;

    let mut claims = BTreeMap::new();
    claims.insert("email".into(), serde_json::json!("alice@example.com"));

    let issued = issue_credential(
        base_input(),
        &claims,
        CryptoAlgorithm::Ed25519,
        &privk,
        &mut rng,
    )
    .unwrap();

    let se = encode_signed_envelope_cbor(&issued.envelope).unwrap();

    let (canon, sig) = decode_signed_envelope_cbor(&se).unwrap();

    verify(CryptoAlgorithm::Ed25519, &pubk, &canon, &sig.raw_rs).unwrap();
}

#[test]
fn signed_envelope_decoder_rejects_malformed_ambiguous_and_oversized_inputs() {
    assert!(decode_signed_envelope_cbor(&[]).is_err());
    assert!(decode_signed_envelope_cbor(&vec![0_u8; OVERSIZED_SIGNED_ENVELOPE_BYTES]).is_err());

    let mut duplicate = Vec::new();
    ciborium::ser::into_writer(
        &ciborium::value::Value::Map(vec![
            (
                ciborium::value::Value::Text("vc_canon".into()),
                ciborium::value::Value::Bytes(vec![1]),
            ),
            (
                ciborium::value::Value::Text("sig_alg".into()),
                ciborium::value::Value::Text("ed25519".into()),
            ),
            (
                ciborium::value::Value::Text("sig_alg".into()),
                ciborium::value::Value::Text("p-256".into()),
            ),
            (
                ciborium::value::Value::Text("verification_method".into()),
                ciborium::value::Value::Text("did:test:issuer#key-1".into()),
            ),
            (
                ciborium::value::Value::Text("sig".into()),
                ciborium::value::Value::Bytes(vec![2]),
            ),
        ]),
        &mut duplicate,
    )
    .unwrap();
    assert!(decode_signed_envelope_cbor(&duplicate).is_err());

    let unknown = encode_dag_cbor(&CborValue::Map(vec![
        ("vc_canon".into(), CborValue::Bytes(vec![1])),
        ("sig_alg".into(), CborValue::String("ed25519".into())),
        (
            "verification_method".into(),
            CborValue::String("did:test:issuer#key-1".into()),
        ),
        ("sig".into(), CborValue::Bytes(vec![2])),
        ("unexpected".into(), CborValue::Bytes(vec![3])),
    ]))
    .unwrap();
    assert!(decode_signed_envelope_cbor(&unknown).is_err());

    let mut trailing = encode_dag_cbor(&CborValue::Map(vec![
        ("vc_canon".into(), CborValue::Bytes(vec![1])),
        ("sig_alg".into(), CborValue::String("ed25519".into())),
        (
            "verification_method".into(),
            CborValue::String("did:test:issuer#key-1".into()),
        ),
        ("sig".into(), CborValue::Bytes(vec![2])),
    ]))
    .unwrap();
    trailing.push(0_u8);
    assert!(decode_signed_envelope_cbor(&trailing).is_err());
}

#[test]
fn signed_envelope_encoder_rejects_non_signing_algorithm() {
    let (_public_key, private_key) = generate_keypair(CryptoAlgorithm::Ed25519).unwrap();
    let mut claims = BTreeMap::new();
    claims.insert("email".into(), serde_json::json!("alice@example.com"));
    let mut issued = issue_credential(
        base_input(),
        &claims,
        CryptoAlgorithm::Ed25519,
        &private_key,
        &mut OsSaltRng,
    )
    .unwrap();

    issued.envelope.issuer_signature.verification_key.alg = CredentialAlgorithm::X25519;
    assert!(encode_signed_envelope_cbor(&issued.envelope).is_err());
}
