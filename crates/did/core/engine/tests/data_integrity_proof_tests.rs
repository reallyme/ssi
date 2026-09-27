// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Test coverage for this crate.
#![allow(missing_docs)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::panic)]
#![allow(clippy::expect_used)]

use reallyme_did_core::{
    create_engine, generate_did_me, CoreVerificationMethod, CreateOptions, UpdatePolicy,
};
use reallyme_did_types::VerificationMethod;
use std::collections::HashMap;

#[test]
fn creates_es256_data_integrity_proof_when_es256_assertion_key_present() {
    let nonce = vec![0; 16];
    let update_policy = UpdatePolicy {
        allowed_verification_methods: vec!["#ed25519".into()],
        threshold: None,
    };
    let canonical_keys = [
        CoreVerificationMethod {
            id: "#ed25519".into(),
            vm_type: "Multikey".into(),
            algorithm: identity_core_primitives::Algorithm::Ed25519,
            public_key_multibase: "zDummyKey".into(),
        },
        CoreVerificationMethod {
            id: "#p256".into(),
            vm_type: "Multikey".into(),
            algorithm: identity_core_primitives::Algorithm::P256,
            public_key_multibase: "zDummyKey".into(),
        },
    ];
    let did = generate_did_me(&nonce, &update_policy, &canonical_keys).unwrap();

    let vm_ed = VerificationMethod {
        id: "#ed25519".into(),
        vm_type: "Multikey".into(),
        controller: did.clone(),
        public_key_multibase: "zDummyKey".into(),
        algorithm: Some("Ed25519".into()),
    };

    let vm_p256 = VerificationMethod {
        id: "#p256".into(),
        vm_type: "Multikey".into(),
        controller: did.clone(),
        public_key_multibase: "zDummyKey".into(),
        algorithm: Some("ES256".into()),
    };

    let opts = CreateOptions {
        id: did.clone(),
        controller: vec![did.clone()],
        sequence: 1,
        prev: None,
        nonce: Some(nonce),

        controller_keys: vec![vm_ed, vm_p256],
        authentication: vec!["#ed25519".into()],
        assertion: vec!["#p256".into()], // ES256 is in assertion
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

    // Provide keys: ED25519 for core signing + P256 for DI proof
    let (_pub_ed, sk_ed) =
        reallyme_crypto::dispatch::generate_keypair(reallyme_crypto::core::Algorithm::Ed25519)
            .unwrap();
    let (_pub_p, sk_p) =
        reallyme_crypto::dispatch::generate_keypair(reallyme_crypto::core::Algorithm::P256)
            .unwrap();

    let mut secrets: HashMap<String, Vec<u8>> = HashMap::new();
    secrets.insert("#ed25519".into(), sk_ed.to_vec());
    secrets.insert("#p256".into(), sk_p.to_vec());

    let res = create_engine(&opts, |id| secrets.get(id).cloned()).unwrap();

    let projected_p256 = res
        .document
        .verification_method
        .iter()
        .find(|vm| vm.id == "#p256")
        .expect("projected P-256 verification method");
    assert_eq!(projected_p256.algorithm.as_deref(), Some("P-256"));

    let proof = res
        .document
        .data_integrity_proof
        .as_ref()
        .expect("expected proof");
    assert_eq!(proof.proof_type, "DataIntegrityProof");
    assert_eq!(proof.cryptosuite.as_deref(), Some("es256-jws-cid-2025"));
    assert_eq!(proof.proof_purpose.as_deref(), Some("assertionMethod"));
    assert_eq!(proof.verification_method.as_deref(), Some("#p256"));
    assert!(proof.created.as_ref().unwrap().ends_with('Z'));
    assert!(proof.jws.as_ref().unwrap().split('.').count() == 3);
}
