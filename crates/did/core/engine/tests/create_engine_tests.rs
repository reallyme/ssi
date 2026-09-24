// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Test coverage for this crate.
#![allow(missing_docs)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::panic)]
#![allow(clippy::expect_used)]

use reallyme_did_core::{create_engine, CreateOptions, DomainVerificationInput, ServiceInput};

use reallyme_did_types::VerificationMethod;

use std::collections::HashMap;

#[test]
fn create_engine_builds_core_cid_and_document() {
    let nonce = vec![0; 16];
    let did = "did:me:test".to_owned();

    // Minimal VM list
    let vm = VerificationMethod {
        id: "#ed25519".into(),
        vm_type: "Multikey".into(),
        controller: did.clone(),
        public_key_multibase: "zDummyKey".into(),
        algorithm: Some("Ed25519".into()),
    };

    let opts = CreateOptions {
        id: did.clone(),
        controller: vec![did.clone()],
        sequence: 1,
        prev: None,
        nonce: Some(nonce),

        controller_keys: vec![vm.clone()],
        authentication: vec!["#ed25519".into()],
        assertion: vec!["#ed25519".into()],
        invocation: vec![],
        key_agreement: vec![],

        services: vec![ServiceInput {
            id: "#svc".into(),
            service_type: "LinkedDomains".into(),
            service_endpoint: serde_json::json!({"origins": ["https://example.com"]}),
        }],

        allowed_verification_methods: vec!["#ed25519".into()],
        threshold: None,

        domain_verification: vec![DomainVerificationInput {
            method: "dns".into(),
            domain: "example.com".into(),
            preset: Some(reallyme_did_core::DomainVerificationPreset::DidMeDefault),
        }],

        also_known_as: vec![],
        hardware_bound: None,
        biometric_protected: None,
        user_verification_method: None,
        device_model: None,
        created: None,
    };

    // Provide a private key for signing (use the real crypto keygen)
    let (public, secret) =
        reallyme_crypto::dispatch::generate_keypair(reallyme_crypto::core::Algorithm::Ed25519)
            .unwrap();
    let mut secrets: HashMap<String, Vec<u8>> = HashMap::new();
    secrets.insert("#ed25519".into(), secret.to_vec());

    let res = create_engine(&opts, |id| secrets.get(id).cloned()).unwrap();

    assert!(!res.core_cbor.is_empty());
    assert!(!res.core_cid.is_empty());
    assert_eq!(res.document.id, did);
    assert_eq!(res.document.current_core, res.core_cid);
    assert_eq!(res.document.verification_method.len(), 1);
    assert_eq!(res.document.verification_method[0].id, "#ed25519");
    assert_eq!(res.document.domain_verification.len(), 1);
    assert_eq!(res.document.domain_verification[0].method, "dns");
    assert!(res.document.service.len() == 1);

    // sanity: core cid string should be parseable
    assert!(reallyme_codec::cbor::is_valid_cid_string(&res.core_cid));
    drop(public);
}

#[test]
fn create_engine_rejects_invalid_first_state() {
    let opts = CreateOptions {
        id: "did:me:test".into(),
        controller: vec!["did:me:test".into()],
        sequence: 1,
        prev: Some("bafyPrevCid".into()), // invalid for first doc
        nonce: Some(vec![0; 16]),

        controller_keys: vec![],
        authentication: vec![],
        assertion: vec![],
        invocation: vec![],
        key_agreement: vec![],
        services: vec![],
        allowed_verification_methods: vec![],
        threshold: None,
        domain_verification: vec![],
        also_known_as: vec![],
        hardware_bound: None,
        biometric_protected: None,
        user_verification_method: None,
        device_model: None,
        created: None,
    };

    assert!(create_engine(&opts, |_| None).is_err());
}
