// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Test coverage for this crate.
#![allow(missing_docs)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::panic)]
#![allow(clippy::expect_used)]

use reallyme_did_types::{Controller, DIDDocument, UpdatePolicy};
use reallyme_ssi_proto_codec::did::{json_to_proto, proto_to_json};

#[test]
fn did_document_roundtrip_json_proto_json() {
    let doc = DIDDocument {
        context: vec![
            "https://www.w3.org/ns/did/v1".into(),
            "https://w3id.org/security/multikey/v1".into(),
        ],
        id: "did:me:123".into(),
        controller: Controller::Single("did:me:123".into()),
        also_known_as: vec![],
        sequence: 1,
        prev: None,
        nonce: Some("AAAAAAAAAAAAAAAAAAAAAA".into()),
        hardware_bound: Some(true),
        biometric_protected: None,
        user_verification_method: None,
        device_model: None,
        core_cbor: "AAAA".into(),
        current_core: "cid123".into(),
        key_history: vec![],
        verification_method: vec![],
        authentication: vec![],
        assertion_method: vec![],
        capability_invocation: vec![],
        key_agreement: vec![],
        service: vec![],
        update_policy: Some(UpdatePolicy {
            allowed_verification_methods: vec!["#ed25519".into()],
            threshold: None,
        }),
        attestations: vec![],
        data_integrity_proof: None,
        domain_verification: vec![],
        eudi_level_of_assurance: None,
        eudi_schema_version: None,
    };

    let proto = json_to_proto(&doc).expect("json_to_proto");
    let back = proto_to_json(&proto).expect("proto_to_json");

    // Core identity
    assert_eq!(doc.id, back.id);
    assert_eq!(doc.sequence, back.sequence);
    assert_eq!(doc.controller, back.controller);

    // Optional metadata
    assert_eq!(doc.hardware_bound, back.hardware_bound);
    assert_eq!(doc.biometric_protected, back.biometric_protected);

    // Core state
    assert_eq!(doc.core_cbor, back.core_cbor);
    assert_eq!(doc.current_core, back.current_core);

    // Policy
    let doc_policy = doc.update_policy.as_ref().unwrap();
    let back_policy = back.update_policy.as_ref().unwrap();
    assert_eq!(
        doc_policy.allowed_verification_methods,
        back_policy.allowed_verification_methods
    );
    assert_eq!(doc_policy.threshold, back_policy.threshold);
}

#[test]
fn controller_array_roundtrip() {
    let doc = DIDDocument {
        context: vec!["https://www.w3.org/ns/did/v1".into()],
        id: "did:me:123".into(),
        controller: Controller::Multiple(vec!["did:me:123".into(), "did:me:456".into()]),
        sequence: 1,
        nonce: Some("AAAAAAAAAAAAAAAAAAAAAA".into()),
        core_cbor: "AAAA".into(),
        current_core: "cid123".into(),
        key_history: vec![],
        verification_method: vec![],
        authentication: vec![],
        assertion_method: vec![],
        capability_invocation: vec![],
        key_agreement: vec![],
        service: vec![],
        update_policy: Some(UpdatePolicy {
            allowed_verification_methods: vec!["#ed25519".into()],
            threshold: None,
        }),
        attestations: vec![],
        domain_verification: vec![],
        also_known_as: vec![],
        prev: None,
        hardware_bound: None,
        biometric_protected: None,
        user_verification_method: None,
        device_model: None,
        data_integrity_proof: None,
        eudi_level_of_assurance: None,
        eudi_schema_version: None,
    };

    let proto = json_to_proto(&doc).unwrap();
    let back = proto_to_json(&proto).unwrap();

    assert_eq!(doc.controller, back.controller);
}
