// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Test coverage for MessagingService pre-key discovery.
#![allow(missing_docs)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::panic)]
#![allow(clippy::expect_used)]

use reallyme_did_api::{
    create::create_did,
    error::DidApiError,
    messaging::{
        designate_messaging_pre_keys, discover_messaging_pre_keys, rotate_messaging_pre_keys,
    },
    profile::DidProfile,
    update::{update_did, UpdateConfig},
    CreateConfig,
};
use reallyme_did_types::Service;
use serde_json::json;
use zeroize::Zeroize;

fn messaging_config() -> CreateConfig {
    CreateConfig {
        profile: Some(DidProfile::Messaging),
        also_known_as: None,
        hardware_bound: None,
        biometric_protected: None,
        user_verification_method: None,
        device_model: None,
        services: None,
        update_policy: None,
        domain_verification: None,
        verification_methods: None,
        authentication: None,
        assertion: None,
        invocation: None,
        key_agreement: None,
        created: None,
    }
}

fn no_op_update_config(service: Service) -> UpdateConfig {
    UpdateConfig {
        services: Some(vec![service]),
        also_known_as: None,
        hardware_bound: None,
        biometric_protected: None,
        user_verification_method: None,
        device_model: None,
        allowed: None,
        threshold: None,
        deactivate: false,
        domain_verification: None,
        rotate_vms: None,
        authentication: None,
        assertion: None,
        invocation: None,
        key_agreement: None,
        created: None,
    }
}

#[test]
fn discover_messaging_pre_keys_returns_transcript_bound_snapshot() {
    let (doc1, ks) =
        create_did(messaging_config(), "did:me:messaging-discover").expect("create_did failed");
    let service = Service {
        id: "#messaging".into(),
        service_type: "MessagingService".into(),
        service_endpoint: json!({
            "uri": "https://relay.example.com/inbox/7f3a",
            "preKeys": ["#x25519", "#mlkem768"]
        }),
    };

    let (doc2, _) =
        update_did(&doc1, &ks, no_op_update_config(service)).expect("update_did failed");
    let mut snapshots = discover_messaging_pre_keys(&doc2).expect("discovery failed");

    assert_eq!(snapshots.len(), 1);
    assert_eq!(snapshots[0].did, doc2.id);
    assert_eq!(snapshots[0].sequence, doc2.sequence);
    assert_eq!(snapshots[0].current_core, doc2.current_core);
    assert_eq!(snapshots[0].service_id, "#messaging");
    assert_eq!(snapshots[0].uri, "https://relay.example.com/inbox/7f3a");
    assert_eq!(snapshots[0].pre_keys, vec!["#x25519", "#mlkem768"]);
    assert_eq!(
        format!("{:?}", snapshots[0]),
        "MessagingPreKeySnapshot(<redacted>)"
    );
    snapshots[0].zeroize();
    assert!(snapshots[0].did.is_empty());
    assert!(snapshots[0].uri.is_empty());
    assert!(snapshots[0].pre_keys.is_empty());
}

#[test]
fn designate_messaging_pre_keys_publishes_valid_snapshot() {
    let (doc1, ks1) =
        create_did(messaging_config(), "did:me:messaging-designate").expect("create_did failed");

    let (doc2, _) = designate_messaging_pre_keys(
        &doc1,
        &ks1,
        "#messaging".into(),
        "https://relay.example.com/inbox/7f3a".into(),
        vec!["#x25519".into(), "#mlkem768".into()],
        None,
    )
    .expect("designation failed");

    let snapshots = discover_messaging_pre_keys(&doc2).expect("discovery failed");

    assert_eq!(snapshots.len(), 1);
    assert_eq!(snapshots[0].pre_keys, vec!["#x25519", "#mlkem768"]);
}

#[test]
fn rotate_messaging_pre_keys_rekeys_designated_key_agreement_methods() {
    let (doc1, ks1) =
        create_did(messaging_config(), "did:me:messaging-rotate").expect("create_did failed");
    let (doc2, ks2) = designate_messaging_pre_keys(
        &doc1,
        &ks1,
        "#messaging".into(),
        "https://relay.example.com/inbox/7f3a".into(),
        vec!["#x25519".into(), "#mlkem768".into()],
        None,
    )
    .expect("designation failed");

    let old_x25519 = ks2.get_public("#x25519").unwrap();
    let old_mlkem768 = ks2.get_public("#mlkem768").unwrap();
    let old_mlkem1024 = ks2.get_public("#mlkem1024").unwrap();

    let (doc3, ks3) =
        rotate_messaging_pre_keys(&doc2, &ks2, "#messaging", None).expect("pre-key rotate failed");

    assert_eq!(doc3.sequence, doc2.sequence + 1);
    assert_ne!(ks3.get_public("#x25519").unwrap(), old_x25519);
    assert_ne!(ks3.get_public("#mlkem768").unwrap(), old_mlkem768);
    assert_eq!(ks3.get_public("#mlkem1024").unwrap(), old_mlkem1024);
}

#[test]
fn designate_messaging_pre_keys_rejects_non_hybrid_set() {
    let (doc1, ks1) = create_did(messaging_config(), "did:me:messaging-designate-invalid")
        .expect("create_did failed");

    let err = designate_messaging_pre_keys(
        &doc1,
        &ks1,
        "#messaging".into(),
        "https://relay.example.com/inbox/7f3a".into(),
        vec!["#x25519".into()],
        None,
    )
    .unwrap_err();

    assert_eq!(err, DidApiError::MessagingPreKeyDesignationInvalid);
}

#[test]
fn discover_messaging_pre_keys_rejects_non_hybrid_pre_key_set() {
    let (mut doc, _) =
        create_did(messaging_config(), "did:me:messaging-invalid").expect("create_did failed");
    doc.service = vec![Service {
        id: "#messaging".into(),
        service_type: "MessagingService".into(),
        service_endpoint: json!({
            "uri": "https://relay.example.com/inbox/7f3a",
            "preKeys": ["#x25519"]
        }),
    }];

    let err = discover_messaging_pre_keys(&doc).unwrap_err();

    assert_eq!(err, DidApiError::MessagingPreKeyDiscoveryInvalid);
}
