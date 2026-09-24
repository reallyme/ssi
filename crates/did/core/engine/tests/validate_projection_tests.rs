// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Test coverage for this crate.
#![allow(missing_docs)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::panic)]
#![allow(clippy::expect_used)]

use reallyme_did_core::validate::{
    validate_projection, DidValidationCode, DidValidationIssue, DidValidationLocation,
};
use reallyme_did_core::{Canonical, CoreVerificationMethod};
use reallyme_did_types::{Controller, DIDDocument, VerificationMethod};

use reallyme_codec::base64url::bytes_to_base64url;
use reallyme_codec::cbor::CborValue;

use identity_core_primitives::Algorithm;
use reallyme_crypto::core::Algorithm as CryptoAlgorithm;
use reallyme_crypto::dispatch::{generate_keypair, public_key_to_multikey};

mod helpers;
use helpers::test_core;

fn has_issue(
    errors: &[DidValidationIssue],
    code: DidValidationCode,
    location: DidValidationLocation,
) -> bool {
    errors
        .iter()
        .any(|issue| issue.code == code && issue.location == location)
}

/// Helper: build a minimal valid DID core + JSON projection
fn make_valid_core_and_doc() -> (CborValue, DIDDocument) {
    // Real multikey (required for parse_multikey checks in projection)
    let (pk, _sk) = generate_keypair(CryptoAlgorithm::Ed25519).unwrap();
    let multikey = public_key_to_multikey(CryptoAlgorithm::Ed25519, &pk).unwrap();

    // --- core (via helper) ---
    let mut core = test_core(1, None);

    core.controller_keys = vec![CoreVerificationMethod {
        id: "#ed25519".into(),
        vm_type: "Multikey".into(),
        algorithm: Algorithm::Ed25519,
        public_key_multibase: multikey.clone(),
    }];

    core.authentication = vec!["#ed25519".into()];
    core.update_policy.allowed_verification_methods = vec!["#ed25519".into()];
    core.update_policy.threshold = None;

    let core_cbor = core.canonical_cbor().unwrap();
    let core_value: CborValue = reallyme_codec::cbor::decode_dag_cbor(&core_cbor).unwrap();

    // --- document projection ---
    let doc = DIDDocument {
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
        core_cbor: bytes_to_base64url(&core_cbor),
        current_core: "bafyTEST".into(),
        key_history: vec![],
        verification_method: vec![VerificationMethod {
            id: "#ed25519".into(),
            vm_type: "Multikey".into(),
            controller: "did:me:test".into(),
            algorithm: Some("Ed25519".into()),
            public_key_multibase: multikey,
        }],
        authentication: vec!["#ed25519".into()],
        assertion_method: vec![],
        capability_invocation: vec!["#ed25519".into()],
        key_agreement: vec![],
        service: vec![],
        update_policy: Some(reallyme_did_types::UpdatePolicy {
            allowed_verification_methods: vec!["#ed25519".into()],
            threshold: None,
        }),
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

    (core_value, doc)
}

#[test]
fn valid_projection_passes() {
    let (core, doc) = make_valid_core_and_doc();

    let res = validate_projection(&doc, &core);

    assert!(res.ok, "{:?}", res.errors);
    assert!(res.errors.is_empty());
}

#[test]
fn missing_verification_method_in_json_fails() {
    let (core, mut doc) = make_valid_core_and_doc();

    doc.verification_method.clear();

    let res = validate_projection(&doc, &core);

    assert!(!res.ok);
    assert!(has_issue(
        &res.errors,
        DidValidationCode::CoreProjectionMismatch,
        DidValidationLocation::VerificationMethod
    ));
}

#[test]
fn extra_verification_method_in_json_fails() {
    let (core, mut doc) = make_valid_core_and_doc();

    doc.verification_method.push(VerificationMethod {
        id: "#extra".into(),
        vm_type: "Multikey".into(),
        controller: "did:me:test".into(),
        algorithm: Some("Ed25519".into()),
        public_key_multibase: doc.verification_method[0].public_key_multibase.clone(),
    });

    let res = validate_projection(&doc, &core);

    assert!(!res.ok);
    assert!(has_issue(
        &res.errors,
        DidValidationCode::CoreProjectionMismatch,
        DidValidationLocation::VerificationMethod
    ));
}

#[test]
fn key_history_sequence_mismatch_fails() {
    let (core, mut doc) = make_valid_core_and_doc();

    doc.key_history.push("bafyOLD".into());

    let res = validate_projection(&doc, &core);

    assert!(!res.ok);
    assert!(has_issue(
        &res.errors,
        DidValidationCode::CoreProjectionMismatch,
        DidValidationLocation::KeyHistory
    ));
}

#[test]
fn update_policy_allowed_mismatch_detected() {
    let (core, mut doc) = make_valid_core_and_doc();

    doc.update_policy
        .as_mut()
        .unwrap()
        .allowed_verification_methods
        .push("#extra".into());

    let res = validate_projection(&doc, &core);

    assert!(!res.ok);
    assert!(has_issue(
        &res.errors,
        DidValidationCode::CoreProjectionMismatch,
        DidValidationLocation::UpdatePolicy
    ));
}

#[test]
fn relationship_mismatch_detected() {
    let (core, mut doc) = make_valid_core_and_doc();

    doc.authentication.clear();

    let res = validate_projection(&doc, &core);

    assert!(!res.ok);
    assert!(has_issue(
        &res.errors,
        DidValidationCode::CoreProjectionMismatch,
        DidValidationLocation::Relationship
    ));
}

#[test]
fn service_mismatch_detected() {
    let (core, doc) = make_valid_core_and_doc();

    // Inject a core service without JSON projection
    let core_with_service = match core {
        CborValue::Map(mut m) => {
            // REMOVE any existing "services" entry
            m.retain(|(k, _)| k != "services");

            // INSERT the new one
            m.push((
                "services".to_string(),
                CborValue::Array(vec![CborValue::Map(vec![
                    ("id".to_string(), CborValue::String("#svc".to_string())),
                    ("type".to_string(), CborValue::String("Example".to_string())),
                    (
                        "serviceEndpoint".to_string(),
                        CborValue::Bytes(br#"{"url":"https://x"}"#.to_vec()),
                    ),
                ])]),
            ));

            CborValue::Map(m)
        }
        _ => panic!("expected core to be a map"),
    };

    let res = validate_projection(&doc, &core_with_service);

    assert!(!res.ok);
    assert!(
        has_issue(
            &res.errors,
            DidValidationCode::CoreProjectionMismatch,
            DidValidationLocation::Service
        ),
        "{:?}",
        res.errors
    );
}
