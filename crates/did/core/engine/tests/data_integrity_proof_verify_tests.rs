// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Test coverage for this crate.
#![allow(missing_docs)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::panic)]
#![allow(clippy::expect_used)]

use envelopes_data_integrity::suites::es256_jws_cid_2025::{
    verify_es256_jws_cid_2025, Es256JwsCid2025Error,
};
use reallyme_did_core::{create_engine, CreateOptions};
use reallyme_did_types::VerificationMethod;

use std::collections::HashMap;

struct ProofFixture {
    opts: CreateOptions,
    secrets: HashMap<String, Vec<u8>>,
}

fn proof_fixture() -> ProofFixture {
    let nonce = vec![0; 16];

    let (pk_ed, sk_ed) =
        reallyme_crypto::dispatch::generate_keypair(reallyme_crypto::core::Algorithm::Ed25519)
            .unwrap();
    let (pk_p, sk_p) =
        reallyme_crypto::dispatch::generate_keypair(reallyme_crypto::core::Algorithm::P256)
            .unwrap();

    let ed_multikey = reallyme_crypto::dispatch::public_key_to_multikey(
        reallyme_crypto::core::Algorithm::Ed25519,
        &pk_ed,
    )
    .unwrap();
    let p256_multikey = reallyme_crypto::dispatch::public_key_to_multikey(
        reallyme_crypto::core::Algorithm::P256,
        &pk_p,
    )
    .unwrap();

    let did = "did:me:test".to_owned();

    let opts = CreateOptions {
        id: did.clone(),
        controller: vec![did.clone()],
        sequence: 1,
        prev: None,
        nonce: Some(nonce),

        controller_keys: vec![
            VerificationMethod {
                id: "#ed25519".into(),
                vm_type: "Multikey".into(),
                controller: did.clone(),
                public_key_multibase: ed_multikey,
                algorithm: Some("Ed25519".into()),
            },
            VerificationMethod {
                id: "#p256".into(),
                vm_type: "Multikey".into(),
                controller: did,
                public_key_multibase: p256_multikey,
                algorithm: Some("P-256".into()),
            },
        ],
        authentication: vec!["#ed25519".into()],
        assertion: vec!["#p256".into()],
        invocation: vec![],
        key_agreement: vec![],

        services: vec![],
        allowed_verification_methods: vec!["#ed25519".into()],
        threshold: None,

        domain_verification: vec![],

        also_known_as: vec![],
        hardware_bound: None,
        biometric_protected: None,
        user_verification_method: None,
        device_model: None,
        created: Some("2025-01-01T00:00:00Z".into()),
    };

    let mut secrets = HashMap::new();
    secrets.insert("#ed25519".into(), sk_ed.to_vec());
    secrets.insert("#p256".into(), sk_p.to_vec());

    ProofFixture { opts, secrets }
}

#[test]
fn verify_proof_succeeds_for_created_document() {
    let fixture = proof_fixture();

    let res = create_engine(&fixture.opts, |id| fixture.secrets.get(id).cloned()).unwrap();

    verify_es256_jws_cid_2025(&res.document).unwrap();
}

#[test]
fn verify_proof_fails_if_current_core_changes() {
    let fixture = proof_fixture();

    let mut res = create_engine(&fixture.opts, |id| fixture.secrets.get(id).cloned()).unwrap();

    // Tamper with currentCore; the JWS payload must match the exact CID string.
    res.document.current_core.push('x');

    let err = verify_es256_jws_cid_2025(&res.document).unwrap_err();

    assert!(matches!(err, Es256JwsCid2025Error::PayloadMismatch));
}

#[test]
fn verify_proof_requires_assertion_method_purpose() {
    let fixture = proof_fixture();

    let mut res = create_engine(&fixture.opts, |id| fixture.secrets.get(id).cloned()).unwrap();
    let proof = res
        .document
        .data_integrity_proof
        .as_mut()
        .expect("expected proof");
    proof.proof_purpose = Some("authentication".into());

    let err = verify_es256_jws_cid_2025(&res.document).unwrap_err();

    assert!(matches!(err, Es256JwsCid2025Error::InvalidInput));
}
