// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Test coverage for this crate.
#![allow(missing_docs)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::panic)]
#![allow(clippy::expect_used)]

use reallyme_did_core::validate::{validate_services, DidValidationCode, DidValidationIssue};
use reallyme_did_types::{DIDDocument, Service, VerificationMethod};

use serde_json::json;

fn base_doc() -> DIDDocument {
    let mut document = DIDDocument::default();
    document.id = "did:me:test".into();
    document
}

fn has_code(errors: &[DidValidationIssue], code: DidValidationCode) -> bool {
    errors.iter().any(|issue| issue.code == code)
}

fn verification_method(id: &str, algorithm: &str) -> VerificationMethod {
    VerificationMethod {
        id: id.into(),
        vm_type: "Multikey".into(),
        controller: "did:me:test".into(),
        public_key_multibase: "zDummyKey".into(),
        algorithm: Some(algorithm.into()),
    }
}

fn messaging_doc(pre_keys: &[&str], key_agreement: &[&str]) -> DIDDocument {
    let mut doc = base_doc();
    doc.verification_method = vec![
        verification_method("#x25519-msg", "X25519"),
        verification_method("#mlkem768-msg", "ML-KEM-768"),
        verification_method("#mlkem1024-msg", "ML-KEM-1024"),
        verification_method("#ed25519", "Ed25519"),
    ];
    doc.key_agreement = key_agreement.iter().map(|value| (*value).into()).collect();
    doc.service.push(Service {
        id: "#messaging".into(),
        service_type: "MessagingService".into(),
        service_endpoint: json!({
            "uri": "https://relay.example.com/inbox/7f3a",
            "preKeys": pre_keys,
        }),
    });
    doc
}

#[test]
fn empty_services_is_ok() {
    let doc = base_doc();
    let res = validate_services(&doc);
    assert!(res.ok);
    assert!(res.errors.is_empty());
}

#[test]
fn valid_service_passes() {
    let mut doc = base_doc();

    doc.service.push(Service {
        id: "#svc".into(),
        service_type: "ExampleService".into(),
        service_endpoint: json!("https://example.com"),
    });

    let res = validate_services(&doc);
    assert!(res.ok, "{:?}", res.errors);
}

#[test]
fn duplicate_service_ids_fail() {
    let mut doc = base_doc();

    doc.service.push(Service {
        id: "#dup".into(),
        service_type: "A".into(),
        service_endpoint: json!("https://a.example"),
    });

    doc.service.push(Service {
        id: "#dup".into(),
        service_type: "B".into(),
        service_endpoint: json!("https://b.example"),
    });

    let res = validate_services(&doc);
    assert!(!res.ok);
    assert!(has_code(&res.errors, DidValidationCode::ServiceInvalid));
}

#[test]
fn missing_service_type_fails() {
    let mut doc = base_doc();

    doc.service.push(Service {
        id: "#svc".into(),
        service_type: "".into(),
        service_endpoint: json!("https://example.com"),
    });

    let res = validate_services(&doc);
    assert!(!res.ok);
    assert!(has_code(&res.errors, DidValidationCode::ServiceInvalid));
}

#[test]
fn missing_service_endpoint_fails() {
    let mut doc = base_doc();

    doc.service.push(Service {
        id: "#svc".into(),
        service_type: "X".into(),
        service_endpoint: serde_json::Value::Null,
    });

    let res = validate_services(&doc);
    assert!(!res.ok);
    assert!(has_code(&res.errors, DidValidationCode::ServiceInvalid));
}

#[test]
fn invalid_service_endpoint_type_fails() {
    let mut doc = base_doc();

    doc.service.push(Service {
        id: "#svc".into(),
        service_type: "X".into(),
        service_endpoint: json!(42),
    });

    let res = validate_services(&doc);
    assert!(!res.ok);
    assert!(has_code(&res.errors, DidValidationCode::ServiceInvalid));
}

#[test]
fn array_and_object_service_endpoints_are_allowed() {
    let mut doc = base_doc();

    doc.service.push(Service {
        id: "#obj".into(),
        service_type: "ObjSvc".into(),
        service_endpoint: json!({ "url": "https://example.com" }),
    });

    doc.service.push(Service {
        id: "#arr".into(),
        service_type: "ArrSvc".into(),
        service_endpoint: json!(["https://a.example", "https://b.example"]),
    });

    let res = validate_services(&doc);
    assert!(res.ok, "{:?}", res.errors);
}

#[test]
fn messaging_service_accepts_x25519_and_mlkem768_pre_keys() {
    let doc = messaging_doc(
        &["#x25519-msg", "#mlkem768-msg"],
        &["#x25519-msg", "#mlkem768-msg"],
    );

    let res = validate_services(&doc);
    assert!(res.ok, "{:?}", res.errors);
}

#[test]
fn messaging_service_accepts_x25519_and_mlkem1024_pre_keys() {
    let doc = messaging_doc(
        &["#x25519-msg", "#mlkem1024-msg"],
        &["#x25519-msg", "#mlkem1024-msg"],
    );

    let res = validate_services(&doc);
    assert!(res.ok, "{:?}", res.errors);
}

#[test]
fn messaging_service_rejects_pre_key_outside_key_agreement() {
    let doc = messaging_doc(
        &["#ed25519", "#mlkem768-msg"],
        &["#x25519-msg", "#mlkem768-msg"],
    );

    let res = validate_services(&doc);
    assert!(!res.ok);
    assert!(has_code(&res.errors, DidValidationCode::ServiceInvalid));
}

#[test]
fn messaging_service_rejects_classical_only_pre_keys() {
    let doc = messaging_doc(&["#x25519-msg"], &["#x25519-msg"]);

    let res = validate_services(&doc);
    assert!(!res.ok);
    assert!(has_code(&res.errors, DidValidationCode::ServiceInvalid));
}

#[test]
fn messaging_service_rejects_duplicate_pre_keys() {
    let doc = messaging_doc(
        &["#x25519-msg", "#x25519-msg", "#mlkem768-msg"],
        &["#x25519-msg", "#mlkem768-msg"],
    );

    let res = validate_services(&doc);
    assert!(!res.ok);
    assert!(has_code(&res.errors, DidValidationCode::ServiceInvalid));
}

#[test]
fn messaging_service_rejects_post_quantum_only_pre_keys() {
    let doc = messaging_doc(&["#mlkem768-msg"], &["#mlkem768-msg"]);

    let res = validate_services(&doc);
    assert!(!res.ok);
    assert!(has_code(&res.errors, DidValidationCode::ServiceInvalid));
}

#[test]
fn messaging_service_rejects_dangling_pre_key_reference() {
    let doc = messaging_doc(
        &["#x25519-msg", "#missing-key"],
        &["#x25519-msg", "#missing-key"],
    );

    let res = validate_services(&doc);
    assert!(!res.ok);
    assert!(has_code(&res.errors, DidValidationCode::ServiceInvalid));
}

#[test]
fn messaging_service_rejects_non_object_endpoint() {
    let mut doc = base_doc();
    doc.service.push(Service {
        id: "#messaging".into(),
        service_type: "MessagingService".into(),
        service_endpoint: json!("https://relay.example.com/inbox/7f3a"),
    });

    let res = validate_services(&doc);
    assert!(!res.ok);
    assert!(has_code(&res.errors, DidValidationCode::ServiceInvalid));
}
