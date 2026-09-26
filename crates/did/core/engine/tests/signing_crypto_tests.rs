// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Test coverage for this crate.
#![allow(missing_docs)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::panic)]
#![allow(clippy::expect_used)]

use identity_core_primitives::Algorithm;
use reallyme_did_core::{
    core_signature_input, sign_core, Canonical, CoreVerificationMethod, DidCore, UpdatePolicy,
};

use reallyme_crypto::core::Algorithm as CryptoAlgorithm;
use reallyme_crypto::dispatch::{generate_keypair, verify};

use std::collections::HashMap;

#[test]
fn signature_verifies_against_domain_separated_core() {
    let core = sample_core();

    // Generate a REAL Ed25519 keypair
    let (public, secret) = generate_keypair(CryptoAlgorithm::Ed25519).unwrap();

    let keys = vec![CoreVerificationMethod {
        id: "#ed25519".into(),
        vm_type: "Multikey".into(),
        algorithm: Algorithm::Ed25519,
        public_key_multibase: "zKey".into(),
    }];

    let mut secrets: HashMap<String, Vec<u8>> = HashMap::new();
    secrets.insert("#ed25519".into(), secret.to_vec());

    let attestations = sign_core(&core, &keys, &["#ed25519".into()], |id| {
        secrets.get(id).cloned()
    })
    .unwrap();

    // 🔒 Audit-critical assertion
    assert_eq!(attestations.len(), 1, "expected exactly one attestation");

    let att = &attestations[0];
    let sig = reallyme_codec::base64url::base64url_to_bytes(&att.signature).unwrap();

    verify(
        CryptoAlgorithm::Ed25519,
        &public,
        &core_signature_input(&core.canonical_cbor().unwrap()).unwrap(),
        &sig,
    )
    .unwrap();
}

#[test]
fn signature_fails_if_core_is_modified() {
    let mut core = sample_core();

    let (public, secret) = generate_keypair(CryptoAlgorithm::Ed25519).unwrap();

    let keys = vec![CoreVerificationMethod {
        id: "#ed25519".into(),
        vm_type: "Multikey".into(),
        algorithm: Algorithm::Ed25519,
        public_key_multibase: "zKey".into(),
    }];

    let mut secrets: HashMap<String, Vec<u8>> = HashMap::new();
    secrets.insert("#ed25519".into(), secret.to_vec());

    let attestations = sign_core(&core, &keys, &["#ed25519".into()], |id| {
        secrets.get(id).cloned()
    })
    .unwrap();

    assert_eq!(attestations.len(), 1, "expected exactly one attestation");

    let att = &attestations[0];

    // Mutate core AFTER signing
    core.sequence += 1;

    let sig = reallyme_codec::base64url::base64url_to_bytes(&att.signature).unwrap();

    assert!(verify(
        CryptoAlgorithm::Ed25519,
        &public,
        &core_signature_input(&core.canonical_cbor().unwrap()).unwrap(),
        &sig,
    )
    .is_err());
}

#[test]
fn tampered_signature_fails_verification() {
    let core = sample_core();

    let (public, secret) = generate_keypair(CryptoAlgorithm::Ed25519).unwrap();

    let keys = vec![CoreVerificationMethod {
        id: "#ed25519".into(),
        vm_type: "Multikey".into(),
        algorithm: Algorithm::Ed25519,
        public_key_multibase: "zKey".into(),
    }];

    let mut secrets: HashMap<String, Vec<u8>> = HashMap::new();
    secrets.insert("#ed25519".into(), secret.to_vec());

    let attestations = sign_core(&core, &keys, &["#ed25519".into()], |id| {
        secrets.get(id).cloned()
    })
    .unwrap();

    assert_eq!(attestations.len(), 1, "expected exactly one attestation");

    let att = &attestations[0];

    let mut sig = reallyme_codec::base64url::base64url_to_bytes(&att.signature).unwrap();
    sig[0] ^= 0xFF; // corrupt signature

    assert!(verify(
        CryptoAlgorithm::Ed25519,
        &public,
        &core_signature_input(&core.canonical_cbor().unwrap()).unwrap(),
        &sig,
    )
    .is_err());
}

fn sample_core() -> DidCore {
    DidCore {
        id: "did:me:test".into(),
        sequence: 1,
        nonce: Some(vec![0; 16]),
        controller: vec!["did:me:test".into()],
        controller_keys: vec![],
        authentication: vec![],
        assertion: vec![],
        key_agreement: vec![],
        services: vec![],
        update_policy: UpdatePolicy {
            allowed_verification_methods: vec!["#ed25519".into()],
            threshold: None,
        },
        prev: None,
    }
}
