// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Test coverage for this crate.
#![allow(missing_docs)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::panic)]
#![allow(clippy::expect_used)]

use reallyme_codec::cbor::CborValue;
use reallyme_did_core::{
    project_did_document, CanonicalService, DidCore, DocumentProjection,
    UpdatePolicy as CoreUpdatePolicy,
};

use reallyme_did_types::VerificationMethod;

#[test]
fn controller_collapses_when_single() {
    let core = sample_core_single_controller();
    let doc = project_did_document(DocumentProjection {
        core: &core,
        core_cid: "bafytestcid",
        also_known_as: vec![],
        hardware_bound: Some(true),
        biometric_protected: None,
        user_verification_method: None,
        device_model: None,
        eudi_level_of_assurance: None,
        eudi_schema_version: None,
        key_history: vec![],
        verification_method: vec![],
        capability_invocation: vec![],
        domain_verification: vec![],
        attestations: vec![],
        data_integrity_proof: None,
    })
    .unwrap();

    match doc.controller {
        reallyme_did_types::Controller::Single(_) => {}
        _ => panic!("expected Single controller"),
    }
}

#[test]
fn services_project_canonical_endpoint_values() {
    let mut core = sample_core_single_controller();
    core.services = vec![CanonicalService {
        id: "#svc".into(),
        service_type: "LinkedDomains".into(),
        service_endpoint: CborValue::Map(vec![(
            "origins".into(),
            CborValue::Array(vec![CborValue::String("https://example.com".into())]),
        )]),
    }];

    let doc = project_did_document(DocumentProjection {
        core: &core,
        core_cid: "bafytestcid",
        also_known_as: vec![],
        hardware_bound: None,
        biometric_protected: None,
        user_verification_method: None,
        device_model: None,
        eudi_level_of_assurance: None,
        eudi_schema_version: None,
        key_history: vec![],
        verification_method: vec![],
        capability_invocation: vec![],
        domain_verification: vec![],
        attestations: vec![],
        data_integrity_proof: None,
    })
    .unwrap();

    assert_eq!(doc.service.len(), 1);
    assert_eq!(doc.service[0].id, "#svc");
    assert_eq!(doc.service[0].service_type, "LinkedDomains");
    assert!(doc.service[0].service_endpoint.is_object());
}

#[test]
fn core_cbor_and_current_core_are_set() {
    let core = sample_core_single_controller();
    let cid = "bafytestcid";

    let doc = project_did_document(DocumentProjection {
        core: &core,
        core_cid: cid,
        also_known_as: vec![],
        hardware_bound: None,
        biometric_protected: None,
        user_verification_method: None,
        device_model: None,
        eudi_level_of_assurance: None,
        eudi_schema_version: None,
        key_history: vec![],
        verification_method: vec![VerificationMethod {
            id: "#ed25519".into(),
            vm_type: "Multikey".into(),
            controller: "did:me:test".into(),
            public_key_multibase: "zDummyKey".into(),
            algorithm: Some("Ed25519".into()),
        }],
        capability_invocation: vec![],
        domain_verification: vec![],
        attestations: vec![],
        data_integrity_proof: None,
    })
    .unwrap();

    assert_eq!(doc.current_core, cid);
    assert!(!doc.core_cbor.is_empty());
}

fn sample_core_single_controller() -> DidCore {
    DidCore {
        id: "did:me:test".into(),
        sequence: 1,
        nonce: Some(vec![0; 16]),
        controller: vec!["did:me:test".into()],
        controller_keys: vec![],
        authentication: vec!["#ed25519".into()],
        assertion: vec!["#ed25519".into()],
        key_agreement: vec![],
        services: vec![],
        update_policy: CoreUpdatePolicy {
            allowed_verification_methods: vec!["#ed25519".into()],
            threshold: None,
        },
        prev: None,
    }
}
