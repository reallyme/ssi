// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Test coverage for this crate.
#![allow(missing_docs)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::panic)]
#![allow(clippy::expect_used)]

use reallyme_did_core::validate::{validate_update_policy, DidValidationCode, DidValidationIssue};
use reallyme_did_types::{Controller, DIDDocument, UpdatePolicy, VerificationMethod};

fn has_code(errors: &[DidValidationIssue], code: DidValidationCode) -> bool {
    errors.iter().any(|issue| issue.code == code)
}

fn base_doc() -> DIDDocument {
    DIDDocument {
        context: vec![],
        id: "did:me:test".into(),
        controller: Controller::Single("did:me:test".into()),
        sequence: 1,
        prev: None,
        nonce: Some("AAAAAAAAAAAAAAAAAAAAAA".into()),
        core_cbor: "abc".into(),
        current_core: "cid".into(),
        key_history: vec![],
        verification_method: vec![
            VerificationMethod {
                id: "#ed25519".into(),
                vm_type: "Multikey".into(),
                controller: "did:me:test".into(),
                algorithm: Some("Ed25519".into()),
                public_key_multibase: "zKey1".into(),
            },
            VerificationMethod {
                id: "#mldsa87".into(),
                vm_type: "Multikey".into(),
                controller: "did:me:test".into(),
                algorithm: Some("ML-DSA-87".into()),
                public_key_multibase: "zKey2".into(),
            },
        ],
        authentication: vec![],
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
    }
}

#[test]
fn missing_update_policy_fails() {
    let doc = base_doc();

    let res = validate_update_policy(&doc);

    assert!(!res.ok);
    assert!(has_code(
        &res.errors,
        DidValidationCode::UpdatePolicyInvalid
    ));
}

#[test]
fn empty_allowed_fails() {
    let mut doc = base_doc();
    doc.update_policy = Some(UpdatePolicy {
        allowed_verification_methods: vec![],
        threshold: None,
    });

    let res = validate_update_policy(&doc);

    assert!(!res.ok);
    assert!(has_code(
        &res.errors,
        DidValidationCode::UpdatePolicyInvalid
    ));
}

#[test]
fn terminal_deactivation_empty_allowed_passes() {
    let mut doc = base_doc();
    doc.sequence = 2;
    doc.prev = Some("cid-previous".into());
    doc.nonce = None;
    doc.verification_method = vec![];
    doc.authentication = vec![];
    doc.assertion_method = vec![];
    doc.capability_invocation = vec![];
    doc.key_agreement = vec![];
    doc.service = vec![];
    doc.update_policy = Some(UpdatePolicy {
        allowed_verification_methods: vec![],
        threshold: None,
    });

    let res = validate_update_policy(&doc);

    assert!(res.ok, "{:?}", res.errors);
    assert!(res.errors.is_empty());
}

#[test]
fn terminal_deactivation_with_threshold_fails() {
    let mut doc = base_doc();
    doc.sequence = 2;
    doc.prev = Some("cid-previous".into());
    doc.nonce = None;
    doc.verification_method = vec![];
    doc.update_policy = Some(UpdatePolicy {
        allowed_verification_methods: vec![],
        threshold: Some(1),
    });

    let res = validate_update_policy(&doc);

    assert!(!res.ok);
    assert!(has_code(
        &res.errors,
        DidValidationCode::UpdatePolicyInvalid
    ));
}

#[test]
fn unknown_allowed_vm_fails() {
    let mut doc = base_doc();
    doc.update_policy = Some(UpdatePolicy {
        allowed_verification_methods: vec!["#does-not-exist".into()],
        threshold: None,
    });

    let res = validate_update_policy(&doc);

    assert!(!res.ok);
    assert!(has_code(
        &res.errors,
        DidValidationCode::UpdatePolicyInvalid
    ));
}

#[test]
fn threshold_greater_than_allowed_methods_fails() {
    let mut doc = base_doc();
    doc.update_policy = Some(UpdatePolicy {
        allowed_verification_methods: vec!["#ed25519".into()],
        threshold: Some(2),
    });

    let res = validate_update_policy(&doc);

    assert!(!res.ok);
    assert!(has_code(
        &res.errors,
        DidValidationCode::UpdatePolicyInvalid
    ));
}

#[test]
fn duplicate_allowed_methods_fail() {
    let mut doc = base_doc();
    doc.update_policy = Some(UpdatePolicy {
        allowed_verification_methods: vec!["#ed25519".into(), "#ed25519".into()],
        threshold: Some(1),
    });

    let res = validate_update_policy(&doc);

    assert!(!res.ok);
    assert!(has_code(
        &res.errors,
        DidValidationCode::UpdatePolicyInvalid
    ));
}

#[test]
fn valid_update_policy_passes() {
    let mut doc = base_doc();
    doc.update_policy = Some(UpdatePolicy {
        allowed_verification_methods: vec!["#ed25519".into(), "#mldsa87".into()],
        threshold: None,
    });

    let res = validate_update_policy(&doc);

    assert!(res.ok, "{:?}", res.errors);
    assert!(res.errors.is_empty());
}
