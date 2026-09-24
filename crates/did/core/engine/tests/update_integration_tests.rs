// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Test coverage for this crate.
#![allow(missing_docs)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::panic)]
#![allow(clippy::expect_used)]

use identity_core_primitives::Algorithm;
use reallyme_did_core::update::{
    update_engine, UpdateMetadata, UpdateOptions, UpdateRelationships,
};
use reallyme_did_core::{
    compute_core_cid, generate_keypair_for_algorithm, public_key_to_multikey_for_algorithm,
    Canonical, CoreVerificationMethod,
};
use std::collections::HashMap;

use reallyme_did_types::{Controller, DIDDocument, UpdatePolicy, VerificationMethod};

use reallyme_codec::base64url::bytes_to_base64url;

// test helper
mod helpers;
use helpers::test_core;

/// Build a fully valid DIDDocument backed by a real canonical core.
/// Returns:
/// - the DIDDocument
/// - the OLD ed25519 secret key bytes (for signing updates)
fn sample_doc() -> (DIDDocument, Vec<u8>) {
    // Generate REAL keys for the existing VMs in the old doc
    let (ed_pk, ed_sk) = generate_keypair_for_algorithm(Algorithm::Ed25519).unwrap();

    let ed_multikey = public_key_to_multikey_for_algorithm(Algorithm::Ed25519, &ed_pk).unwrap();

    let (x_pk, _x_sk) = generate_keypair_for_algorithm(Algorithm::X25519).unwrap();
    let x_multikey = public_key_to_multikey_for_algorithm(Algorithm::X25519, &x_pk).unwrap();

    // Build canonical core snapshot that matches the doc projection
    let mut core = test_core(1, None);

    core.controller_keys = vec![
        CoreVerificationMethod {
            id: "#ed25519".into(),
            vm_type: "Multikey".into(),
            algorithm: Algorithm::Ed25519,
            public_key_multibase: ed_multikey.clone(),
        },
        CoreVerificationMethod {
            id: "#x25519".into(),
            vm_type: "Multikey".into(),
            algorithm: Algorithm::X25519,
            public_key_multibase: x_multikey.clone(),
        },
    ];

    core.authentication = vec!["#ed25519".into()];
    core.key_agreement = vec!["#x25519".into()];

    // Old core policy: Ed25519 is allowed to sign updates
    core.update_policy.allowed_verification_methods = vec!["#ed25519".into()];

    let core_cbor_bytes = core.canonical_cbor().unwrap();
    let core_cbor_b64 = bytes_to_base64url(&core_cbor_bytes);
    let current_core = compute_core_cid(&core).unwrap();

    let doc = DIDDocument {
        context: vec!["https://www.w3.org/ns/did/v1".into()],
        id: "did:me:test".into(),
        controller: Controller::Single("did:me:test".into()),
        also_known_as: vec![],
        sequence: 1,
        prev: None,
        nonce: Some("AAAAAAAAAAAAAAAAAAAAAA".into()),
        hardware_bound: None,
        biometric_protected: None,
        user_verification_method: None,
        device_model: None,

        core_cbor: core_cbor_b64,
        current_core,
        key_history: vec![],

        verification_method: vec![
            VerificationMethod {
                id: "#ed25519".into(),
                vm_type: "Multikey".into(),
                controller: "did:me:test".into(),
                public_key_multibase: ed_multikey,
                algorithm: Some("Ed25519".into()),
            },
            VerificationMethod {
                id: "#x25519".into(),
                vm_type: "Multikey".into(),
                controller: "did:me:test".into(),
                public_key_multibase: x_multikey,
                algorithm: Some("X25519".into()),
            },
        ],
        authentication: vec!["#ed25519".into()],
        assertion_method: vec![],
        capability_invocation: vec!["#ed25519".into()],
        key_agreement: vec!["#x25519".into()],
        service: vec![],
        update_policy: Some(UpdatePolicy {
            allowed_verification_methods: vec!["#ed25519".into()],
            threshold: None,
        }),
        domain_verification: vec![],
        attestations: vec![],
        data_integrity_proof: None,
        eudi_level_of_assurance: None,
        eudi_schema_version: None,
    };

    (doc, ed_sk.to_vec())
}

fn sample_doc_with_two_update_keys(
    allowed: Vec<String>,
    threshold: Option<u64>,
) -> (DIDDocument, Vec<u8>, Vec<u8>) {
    let (ed1_pk, ed1_sk) = generate_keypair_for_algorithm(Algorithm::Ed25519).unwrap();
    let ed1_multikey = public_key_to_multikey_for_algorithm(Algorithm::Ed25519, &ed1_pk).unwrap();

    let (ed2_pk, ed2_sk) = generate_keypair_for_algorithm(Algorithm::Ed25519).unwrap();
    let ed2_multikey = public_key_to_multikey_for_algorithm(Algorithm::Ed25519, &ed2_pk).unwrap();

    let mut core = test_core(1, None);
    core.controller_keys = vec![
        CoreVerificationMethod {
            id: "#ed25519".into(),
            vm_type: "Multikey".into(),
            algorithm: Algorithm::Ed25519,
            public_key_multibase: ed1_multikey.clone(),
        },
        CoreVerificationMethod {
            id: "#ed2".into(),
            vm_type: "Multikey".into(),
            algorithm: Algorithm::Ed25519,
            public_key_multibase: ed2_multikey.clone(),
        },
    ];
    core.authentication = vec!["#ed25519".into(), "#ed2".into()];
    core.update_policy.allowed_verification_methods = allowed.clone();
    core.update_policy.threshold = threshold;

    let core_cbor_bytes = core.canonical_cbor().unwrap();
    let core_cbor_b64 = bytes_to_base64url(&core_cbor_bytes);
    let current_core = compute_core_cid(&core).unwrap();

    let doc = DIDDocument {
        context: vec!["https://www.w3.org/ns/did/v1".into()],
        id: "did:me:test".into(),
        controller: Controller::Single("did:me:test".into()),
        also_known_as: vec![],
        sequence: 1,
        prev: None,
        nonce: Some("AAAAAAAAAAAAAAAAAAAAAA".into()),
        hardware_bound: None,
        biometric_protected: None,
        user_verification_method: None,
        device_model: None,
        core_cbor: core_cbor_b64,
        current_core,
        key_history: vec![],
        verification_method: vec![
            VerificationMethod {
                id: "#ed25519".into(),
                vm_type: "Multikey".into(),
                controller: "did:me:test".into(),
                public_key_multibase: ed1_multikey,
                algorithm: Some("Ed25519".into()),
            },
            VerificationMethod {
                id: "#ed2".into(),
                vm_type: "Multikey".into(),
                controller: "did:me:test".into(),
                public_key_multibase: ed2_multikey,
                algorithm: Some("Ed25519".into()),
            },
        ],
        authentication: vec!["#ed25519".into(), "#ed2".into()],
        assertion_method: vec![],
        capability_invocation: allowed.clone(),
        key_agreement: vec![],
        service: vec![],
        update_policy: Some(UpdatePolicy {
            allowed_verification_methods: allowed,
            threshold,
        }),
        domain_verification: vec![],
        attestations: vec![],
        data_integrity_proof: None,
        eudi_level_of_assurance: None,
        eudi_schema_version: None,
    };

    (doc, ed1_sk.to_vec(), ed2_sk.to_vec())
}

#[test]
fn rotates_only_marked_keys() {
    let (old, ed_sk) = sample_doc();

    let mut rotate = HashMap::new();
    rotate.insert("#ed25519".into(), true);

    let (new_ed_pk, _new_ed_sk) = generate_keypair_for_algorithm(Algorithm::Ed25519).unwrap();
    let new_ed_multikey =
        public_key_to_multikey_for_algorithm(Algorithm::Ed25519, &new_ed_pk).unwrap();

    let mut pubs: HashMap<String, String> = HashMap::new();
    pubs.insert("#ed25519".into(), new_ed_multikey.clone());

    let res = update_engine(
        UpdateOptions {
            old: &old,
            rotate,
            allowed: vec!["#ed25519".into()],
            threshold: None,
            deactivate: false,
            services: None,
            domain_verification: None,
            relationships: UpdateRelationships::inherit(),
            metadata: UpdateMetadata {
                also_known_as: None,
                hardware_bound: None,
                biometric_protected: None,
                user_verification_method: None,
                device_model: None,
            },
            created: None,
        },
        |id| {
            if id == "#ed25519" {
                Some(ed_sk.clone())
            } else {
                None
            }
        },
        |id| {
            if id == "#ed25519" {
                Some(ed_sk.clone())
            } else {
                None
            }
        },
        |id| pubs.get(id).cloned(),
    )
    .unwrap();

    let ed = res
        .verification_method
        .iter()
        .find(|v| v.id == "#ed25519")
        .unwrap();
    let x = res
        .verification_method
        .iter()
        .find(|v| v.id == "#x25519")
        .unwrap();

    assert_eq!(ed.public_key_multibase, new_ed_multikey);
    assert_eq!(
        x.public_key_multibase,
        old.verification_method
            .iter()
            .find(|v| v.id == "#x25519")
            .unwrap()
            .public_key_multibase
    );
}

#[test]
fn rotation_preserves_vm_identity() {
    let (old, ed_sk) = sample_doc();

    let mut rotate = HashMap::new();
    rotate.insert("#ed25519".into(), true);

    let (new_pk, _) = generate_keypair_for_algorithm(Algorithm::Ed25519).unwrap();
    let new_multikey = public_key_to_multikey_for_algorithm(Algorithm::Ed25519, &new_pk).unwrap();

    let mut pubs: HashMap<String, String> = HashMap::new();
    pubs.insert("#ed25519".into(), new_multikey.clone());

    let res = update_engine(
        UpdateOptions {
            old: &old,
            rotate,
            allowed: vec!["#ed25519".into()],
            threshold: None,
            deactivate: false,
            services: None,
            domain_verification: None,
            relationships: UpdateRelationships::inherit(),
            metadata: empty_metadata(),
            created: None,
        },
        |_| Some(ed_sk.clone()),
        |_| Some(ed_sk.clone()),
        |id| pubs.get(id).cloned(),
    )
    .unwrap();

    let old_vm = old
        .verification_method
        .iter()
        .find(|v| v.id == "#ed25519")
        .unwrap();
    let new_vm = res
        .verification_method
        .iter()
        .find(|v| v.id == "#ed25519")
        .unwrap();

    assert_eq!(old_vm.id, new_vm.id);
}

#[test]
fn rotation_is_selective() {
    let (old, ed_sk) = sample_doc();

    let mut rotate = HashMap::new();
    rotate.insert("#ed25519".into(), true);

    let (new_pk, _) = generate_keypair_for_algorithm(Algorithm::Ed25519).unwrap();
    let new_multikey = public_key_to_multikey_for_algorithm(Algorithm::Ed25519, &new_pk).unwrap();

    let mut pubs: HashMap<String, String> = HashMap::new();
    pubs.insert("#ed25519".into(), new_multikey.clone());

    let res = update_engine(
        UpdateOptions {
            old: &old,
            rotate,
            allowed: vec!["#ed25519".into()],
            threshold: None,
            deactivate: false,
            services: None,
            domain_verification: None,
            relationships: UpdateRelationships::inherit(),
            metadata: empty_metadata(),
            created: None,
        },
        |_| Some(ed_sk.clone()),
        |_| Some(ed_sk.clone()),
        |id| pubs.get(id).cloned(),
    )
    .unwrap();

    let ed = res
        .verification_method
        .iter()
        .find(|v| v.id.ends_with("#ed25519"))
        .unwrap();
    let x = res
        .verification_method
        .iter()
        .find(|v| v.id.ends_with("#x25519"))
        .unwrap();

    assert_ne!(
        ed.public_key_multibase,
        old.verification_method
            .iter()
            .find(|v| v.id.ends_with("#ed25519"))
            .unwrap()
            .public_key_multibase
    );

    assert_eq!(
        x.public_key_multibase,
        old.verification_method
            .iter()
            .find(|v| v.id.ends_with("#x25519"))
            .unwrap()
            .public_key_multibase
    );
}

#[test]
fn rotation_preserves_vm_order_and_count() {
    let (old, ed_sk) = sample_doc();

    let mut rotate = HashMap::new();
    rotate.insert("#ed25519".into(), true);

    let (new_pk, _) = generate_keypair_for_algorithm(Algorithm::Ed25519).unwrap();
    let new_multikey = public_key_to_multikey_for_algorithm(Algorithm::Ed25519, &new_pk).unwrap();

    let mut pubs: HashMap<String, String> = HashMap::new();
    pubs.insert("#ed25519".into(), new_multikey);

    let res = update_engine(
        UpdateOptions {
            old: &old,
            rotate,
            allowed: vec!["#ed25519".into()],
            threshold: None,
            deactivate: false,
            services: None,
            domain_verification: None,
            relationships: UpdateRelationships::inherit(),
            metadata: empty_metadata(),
            created: None,
        },
        |_| Some(ed_sk.clone()),
        |_| Some(ed_sk.clone()),
        |id| pubs.get(id).cloned(),
    )
    .unwrap();

    assert_eq!(
        old.verification_method
            .iter()
            .map(|v| &v.id)
            .collect::<Vec<_>>(),
        res.verification_method
            .iter()
            .map(|v| &v.id)
            .collect::<Vec<_>>(),
    );
}

#[test]
fn rotation_satisfies_allowed_threshold_policy() {
    let (old, ed_sk) = sample_doc();

    let mut rotate = HashMap::new();
    rotate.insert("#ed25519".into(), true);

    let (new_pk, _) = generate_keypair_for_algorithm(Algorithm::Ed25519).unwrap();
    let new_multikey = public_key_to_multikey_for_algorithm(Algorithm::Ed25519, &new_pk).unwrap();

    let mut pubs: HashMap<String, String> = HashMap::new();
    pubs.insert("#ed25519".into(), new_multikey);

    let res = update_engine(
        UpdateOptions {
            old: &old,
            rotate,
            allowed: vec!["#ed25519".into()],
            threshold: None,
            deactivate: false,
            services: None,
            domain_verification: None,
            relationships: UpdateRelationships::inherit(),
            metadata: empty_metadata(),
            created: None,
        },
        |_| Some(ed_sk.clone()),
        |_| Some(ed_sk.clone()),
        |id| pubs.get(id).cloned(),
    );

    assert!(res.is_ok());
}

#[test]
fn update_authorization_uses_previous_policy_when_new_policy_raises_threshold() {
    let (old, ed1_sk, _) = sample_doc_with_two_update_keys(vec!["#ed25519".into()], None);

    let res = update_engine(
        UpdateOptions {
            old: &old,
            rotate: HashMap::new(),
            allowed: vec!["#ed25519".into(), "#ed2".into()],
            threshold: Some(2),
            deactivate: false,
            services: None,
            domain_verification: None,
            relationships: UpdateRelationships::inherit(),
            metadata: empty_metadata(),
            created: None,
        },
        |id| {
            if id == "#ed25519" {
                Some(ed1_sk.clone())
            } else {
                None
            }
        },
        |id| {
            if id == "#ed25519" {
                Some(ed1_sk.clone())
            } else {
                None
            }
        },
        |_| None,
    )
    .unwrap();

    assert_eq!(res.attestations.len(), 1);
    assert_eq!(res.attestations[0].vm, "#ed25519");
    assert_eq!(
        res.update_policy
            .as_ref()
            .and_then(|policy| policy.threshold),
        Some(2)
    );
}

#[test]
fn update_authorization_keeps_previous_threshold_when_new_policy_lowers_threshold() {
    let (old, ed1_sk, _) =
        sample_doc_with_two_update_keys(vec!["#ed25519".into(), "#ed2".into()], Some(2));

    let res = update_engine(
        UpdateOptions {
            old: &old,
            rotate: HashMap::new(),
            allowed: vec!["#ed25519".into()],
            threshold: Some(1),
            deactivate: false,
            services: None,
            domain_verification: None,
            relationships: UpdateRelationships::inherit(),
            metadata: empty_metadata(),
            created: None,
        },
        |id| {
            if id == "#ed25519" {
                Some(ed1_sk.clone())
            } else {
                None
            }
        },
        |id| {
            if id == "#ed25519" {
                Some(ed1_sk.clone())
            } else {
                None
            }
        },
        |_| None,
    );

    assert!(
        res.is_err(),
        "old threshold=2 must authorize the transition even when the new policy lowers threshold"
    );
}

#[test]
fn rotation_is_signed_by_old_key() {
    let (old, ed_sk) = sample_doc();

    let mut rotate = HashMap::new();
    rotate.insert("#ed25519".into(), true);

    let (new_pk, _) = generate_keypair_for_algorithm(Algorithm::Ed25519).unwrap();
    let new_multikey = public_key_to_multikey_for_algorithm(Algorithm::Ed25519, &new_pk).unwrap();

    let mut pubs: HashMap<String, String> = HashMap::new();
    pubs.insert("#ed25519".into(), new_multikey);

    let res = update_engine(
        UpdateOptions {
            old: &old,
            rotate,
            allowed: vec!["#ed25519".into()],
            threshold: None,
            deactivate: false,
            services: None,
            domain_verification: None,
            relationships: UpdateRelationships::inherit(),
            metadata: empty_metadata(),
            created: None,
        },
        |id| {
            if id == "#ed25519" {
                Some(ed_sk.clone())
            } else {
                None
            }
        },
        |id| {
            if id == "#ed25519" {
                Some(ed_sk.clone())
            } else {
                None
            }
        },
        |id| pubs.get(id).cloned(),
    )
    .unwrap();

    assert!(!res.attestations.is_empty());
}

fn empty_metadata() -> UpdateMetadata {
    UpdateMetadata {
        also_known_as: None,
        hardware_bound: None,
        biometric_protected: None,
        user_verification_method: None,
        device_model: None,
    }
}
