// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Test coverage for this crate.
#![allow(missing_docs)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::panic)]
#![allow(clippy::expect_used)]

use reallyme_did_core::validate::{validate_data_integrity_proof_schema, DidValidationCode};
use reallyme_did_types::{DIDDocument, DataIntegrityProof};

fn base_doc() -> DIDDocument {
    let mut document = DIDDocument::default();
    document.id = "did:me:test".into();
    document
}

fn has_code(
    errors: &[reallyme_did_core::validate::DidValidationIssue],
    code: DidValidationCode,
) -> bool {
    errors.iter().any(|issue| issue.code == code)
}

#[test]
fn no_proof_is_ok() {
    let doc = base_doc();
    let res = validate_data_integrity_proof_schema(&doc);
    assert!(res.ok);
    assert!(res.errors.is_empty());
}

#[test]
fn valid_proof_schema_passes() {
    let mut doc = base_doc();
    doc.data_integrity_proof = Some(DataIntegrityProof {
        proof_type: "DataIntegrityProof".into(),
        cryptosuite: Some("es256-jws-cid-2025".into()),
        proof_purpose: Some("assertionMethod".into()),
        verification_method: Some("#p256".into()),
        created: Some("2025-01-01T00:00:00Z".into()),
        jws: Some("aGVhZGVy.cGF5bG9hZA.c2lnbmF0dXJl".into()),
    });

    let res = validate_data_integrity_proof_schema(&doc);
    assert!(res.ok, "{:?}", res.errors);
    assert!(res.errors.is_empty());
}

#[test]
fn invalid_type_fails() {
    let mut doc = base_doc();
    doc.data_integrity_proof = Some(DataIntegrityProof {
        proof_type: "WrongType".into(),
        cryptosuite: Some("es256-jws-cid-2025".into()),
        proof_purpose: Some("assertionMethod".into()),
        verification_method: Some("#p256".into()),
        created: Some("2025-01-01T00:00:00Z".into()),
        jws: Some("a.b.c".into()),
    });

    let res = validate_data_integrity_proof_schema(&doc);
    assert!(!res.ok);
    assert!(has_code(
        &res.errors,
        DidValidationCode::DataIntegrityProofInvalid
    ));
}

#[test]
fn invalid_cryptosuite_fails() {
    let mut doc = base_doc();
    doc.data_integrity_proof = Some(DataIntegrityProof {
        proof_type: "DataIntegrityProof".into(),
        cryptosuite: Some("wrong-suite".into()),
        proof_purpose: Some("assertionMethod".into()),
        verification_method: Some("#p256".into()),
        created: Some("2025-01-01T00:00:00Z".into()),
        jws: Some("a.b.c".into()),
    });

    let res = validate_data_integrity_proof_schema(&doc);
    assert!(!res.ok);
    assert!(has_code(
        &res.errors,
        DidValidationCode::DataIntegrityProofInvalid
    ));
}

#[test]
fn invalid_verification_method_fails() {
    let mut doc = base_doc();
    doc.data_integrity_proof = Some(DataIntegrityProof {
        proof_type: "DataIntegrityProof".into(),
        cryptosuite: Some("es256-jws-cid-2025".into()),
        proof_purpose: Some("assertionMethod".into()),
        verification_method: Some("not-a-fragment".into()),
        created: Some("2025-01-01T00:00:00Z".into()),
        jws: Some("a.b.c".into()),
    });

    let res = validate_data_integrity_proof_schema(&doc);
    assert!(!res.ok);
    assert!(has_code(
        &res.errors,
        DidValidationCode::DataIntegrityProofInvalid
    ));
}

#[test]
fn created_value_is_informational() {
    let mut doc = base_doc();
    doc.data_integrity_proof = Some(DataIntegrityProof {
        proof_type: "DataIntegrityProof".into(),
        cryptosuite: Some("es256-jws-cid-2025".into()),
        proof_purpose: Some("assertionMethod".into()),
        verification_method: Some("#p256".into()),
        created: Some("2025-01-01T00:00:00+01:00".into()),
        jws: Some("a.b.c".into()),
    });

    let res = validate_data_integrity_proof_schema(&doc);
    assert!(res.ok, "{:?}", res.errors);
    assert!(res.errors.is_empty());
}

#[test]
fn missing_created_fails_shape_validation() {
    let mut doc = base_doc();
    doc.data_integrity_proof = Some(DataIntegrityProof {
        proof_type: "DataIntegrityProof".into(),
        cryptosuite: Some("es256-jws-cid-2025".into()),
        proof_purpose: Some("assertionMethod".into()),
        verification_method: Some("#p256".into()),
        created: None,
        jws: Some("a.b.c".into()),
    });

    let res = validate_data_integrity_proof_schema(&doc);
    assert!(!res.ok);
    assert!(has_code(
        &res.errors,
        DidValidationCode::DataIntegrityProofInvalid
    ));
}

#[test]
fn jws_must_be_compact_and_base64urlish() {
    let mut doc = base_doc();
    doc.data_integrity_proof = Some(DataIntegrityProof {
        proof_type: "DataIntegrityProof".into(),
        cryptosuite: Some("es256-jws-cid-2025".into()),
        proof_purpose: Some("assertionMethod".into()),
        verification_method: Some("#p256".into()),
        created: Some("2025-01-01T00:00:00Z".into()),
        jws: Some("not-a-jws".into()),
    });

    let res = validate_data_integrity_proof_schema(&doc);
    assert!(!res.ok);
    assert!(has_code(
        &res.errors,
        DidValidationCode::DataIntegrityProofInvalid
    ));
}
