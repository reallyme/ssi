// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Test coverage for this crate.
#![allow(missing_docs)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::panic)]
#![allow(clippy::expect_used)]

use reallyme_did_core::validate::{
    validate_did_me_structure, DidValidationCode, DidValidationIssue,
};
use reallyme_did_types::{Controller, DIDDocument, VerificationMethod};

// DID documents erase their owned identity data on drop. Rust therefore disallows
// struct-update syntax; this test-only constructor keeps fixtures readable without
// bypassing the production destructor.
macro_rules! did_document {
    ($($field:ident: $value:expr),+ $(,)?) => {{
        let mut document = DIDDocument::default();
        $(document.$field = $value;)+
        document
    }};
}

fn has_code(errors: &[DidValidationIssue], code: DidValidationCode) -> bool {
    errors.iter().any(|issue| issue.code == code)
}

#[test]
fn valid_document_passes_structure_validation() {
    let doc = did_document! {
        context: vec![
            "https://www.w3.org/ns/did/v1".into(),
            "https://w3id.org/security/multikey/v1".into(),
            "https://did-me.org/ns/did-me/v1".into(),
        ],
        id: "did:me:test".into(),
        controller: Controller::Single("did:me:test".into()),
        sequence: 1,
        prev: None,
        nonce: Some("AAAAAAAAAAAAAAAAAAAAAA".into()),
        core_cbor: "abc".into(),
        current_core: "cid".into(),
        key_history: vec![],

        // OK REQUIRED: at least one verification method
        verification_method: vec![VerificationMethod {
            id: "#ed25519".into(),
            controller: "did:me:test".into(),
            vm_type: "Multikey".into(),
            algorithm: Some("Ed25519".into()),
            public_key_multibase: "zDummyKey".into(),
        }],

        authentication: vec!["#ed25519".into()],
        assertion_method: vec![],
        capability_invocation: vec![],
        key_agreement: vec![],
        service: vec![],
        update_policy: None,
        attestations: vec![],
        data_integrity_proof: None,
        also_known_as: vec![],
        hardware_bound: None,
        biometric_protected: None,
        user_verification_method: None,
        device_model: None,
        domain_verification: vec![],
        eudi_level_of_assurance: None,
        eudi_schema_version: None,
    };

    let res = validate_did_me_structure(&doc);
    assert!(res.ok, "{:?}", res.errors);
}

#[test]
fn invalid_sequence_is_rejected() {
    let doc = did_document! {
        id: "did:me:test".into(),
        sequence: 0,
    };

    let res = validate_did_me_structure(&doc);
    assert!(!res.ok);
}

#[test]
fn context_with_three_entries_is_accepted() {
    let doc = did_document! {
        context: vec![
            "https://www.w3.org/ns/did/v1".into(),
            "https://w3id.org/security/multikey/v1".into(),
            "https://did-me.org/ns/did-me/v1".into(),
        ],
        id: "did:me:test".into(),
        controller: Controller::Single("did:me:test".into()),
        sequence: 1,
        nonce: Some("AAAAAAAAAAAAAAAAAAAAAA".into()),
        core_cbor: "abc".into(),
        current_core: "cid".into(),
        verification_method: vec![VerificationMethod {
            id: "#ed25519".into(),
            controller: "did:me:test".into(),
            vm_type: "Multikey".into(),
            algorithm: Some("Ed25519".into()),
            public_key_multibase: "zDummyKey".into(),
        }],
    };

    let res = validate_did_me_structure(&doc);
    assert!(res.ok, "{:?}", res.errors);
}

#[test]
fn context_with_four_entries_is_accepted() {
    let doc = did_document! {
        context: vec![
            "https://www.w3.org/ns/did/v1".into(),
            "https://w3id.org/security/multikey/v1".into(),
            "https://did-me.org/ns/did-me/v1".into(),
            "https://example.com/extra-context".into(),
        ],
        id: "did:me:test".into(),
        controller: Controller::Single("did:me:test".into()),
        sequence: 1,
        nonce: Some("AAAAAAAAAAAAAAAAAAAAAA".into()),
        core_cbor: "abc".into(),
        current_core: "cid".into(),
        verification_method: vec![VerificationMethod {
            id: "#ed25519".into(),
            controller: "did:me:test".into(),
            vm_type: "Multikey".into(),
            algorithm: Some("Ed25519".into()),
            public_key_multibase: "zDummyKey".into(),
        }],
    };

    let res = validate_did_me_structure(&doc);
    assert!(res.ok, "{:?}", res.errors);
}

#[test]
fn context_wrong_order_is_rejected() {
    let doc = did_document! {
        context: vec![
            "https://w3id.org/security/multikey/v1".into(),
            "https://www.w3.org/ns/did/v1".into(),
            "https://did-me.org/ns/did-me/v1".into(),
        ],
        id: "did:me:test".into(),
        controller: Controller::Single("did:me:test".into()),
        sequence: 1,
        nonce: Some("AAAAAAAAAAAAAAAAAAAAAA".into()),
        core_cbor: "abc".into(),
        current_core: "cid".into(),
        verification_method: vec![VerificationMethod {
            id: "#ed25519".into(),
            controller: "did:me:test".into(),
            vm_type: "Multikey".into(),
            algorithm: Some("Ed25519".into()),
            public_key_multibase: "zDummyKey".into(),
        }],
    };

    let res = validate_did_me_structure(&doc);
    assert!(!res.ok);
    assert!(
        has_code(&res.errors, DidValidationCode::ContextInvalid),
        "errors: {:?}",
        res.errors
    );
}

#[test]
fn duplicate_context_is_rejected() {
    let doc = did_document! {
        context: vec![
            "https://www.w3.org/ns/did/v1".into(),
            "https://w3id.org/security/multikey/v1".into(),
            "https://did-me.org/ns/did-me/v1".into(),
            "https://did-me.org/ns/did-me/v1".into(),
        ],
        id: "did:me:test".into(),
        controller: Controller::Single("did:me:test".into()),
        sequence: 1,
        nonce: Some("AAAAAAAAAAAAAAAAAAAAAA".into()),
        core_cbor: "abc".into(),
        current_core: "cid".into(),
        verification_method: vec![VerificationMethod {
            id: "#ed25519".into(),
            controller: "did:me:test".into(),
            vm_type: "Multikey".into(),
            algorithm: Some("Ed25519".into()),
            public_key_multibase: "zDummyKey".into(),
        }],
    };

    let res = validate_did_me_structure(&doc);
    assert!(!res.ok);
    assert!(
        has_code(&res.errors, DidValidationCode::ContextInvalid),
        "errors: {:?}",
        res.errors
    );
}

#[test]
fn duplicate_relationship_references_are_rejected() {
    let doc = did_document! {
        context: vec![
            "https://www.w3.org/ns/did/v1".into(),
            "https://w3id.org/security/multikey/v1".into(),
            "https://did-me.org/ns/did-me/v1".into(),
        ],
        id: "did:me:test".into(),
        controller: Controller::Single("did:me:test".into()),
        sequence: 1,
        nonce: Some("AAAAAAAAAAAAAAAAAAAAAA".into()),
        core_cbor: "abc".into(),
        current_core: "cid".into(),
        verification_method: vec![VerificationMethod {
            id: "#ed25519".into(),
            controller: "did:me:test".into(),
            vm_type: "Multikey".into(),
            algorithm: Some("Ed25519".into()),
            public_key_multibase: "zDummyKey".into(),
        }],
        authentication: vec!["#ed25519".into(), "#ed25519".into()],
    };

    let res = validate_did_me_structure(&doc);

    assert!(!res.ok);
    assert!(
        has_code(&res.errors, DidValidationCode::RelationshipInvalid),
        "errors: {:?}",
        res.errors
    );
}
