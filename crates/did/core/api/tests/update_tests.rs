// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Test coverage for this crate.
#![allow(missing_docs)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::panic)]
#![allow(clippy::expect_used)]

use reallyme_did_api::{
    create::create_did,
    error::DidApiError,
    profile::DidProfile,
    update::{
        deactivate_did, deactivate_did_validated, set_key_relationships, update_did,
        RelationshipAssignmentConfig, UpdateConfig,
    },
    validate::{validate_did, DomainVerificationEnv},
    CreateConfig, KeySet,
};

#[test]
fn update_without_changes_produces_new_core_and_sequence() {
    let did = "did:me:update-test";

    let (doc1, ks1) = create_did(
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
            created: Some("2025-01-01T00:00:00Z".into()),
        },
        did,
    )
    .expect("create_did failed");

    let (doc2, ks2) = update_did(
        &doc1,
        &ks1,
        UpdateConfig {
            services: None,
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
            created: Some("2025-01-01T00:00:00Z".into()),
        },
    )
    .expect("update_did failed");

    // --- chain semantics ---
    assert_eq!(doc2.sequence, doc1.sequence + 1);
    assert_eq!(doc2.prev, Some(doc1.current_core.clone()));
    assert_ne!(doc2.current_core, doc1.current_core);

    // --- keyset cloned, not regenerated ---
    assert_eq!(
        ks1.get_private("#ed25519").unwrap(),
        ks2.get_private("#ed25519").unwrap(),
        "private keys must be preserved when not rotating"
    );
}

#[test]
fn update_can_modify_metadata_only() {
    let did = "did:me:update-metadata";

    let (doc1, ks) = create_did(
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
            created: Some("2025-01-01T00:00:00Z".into()),
        },
        did,
    )
    .expect("create_did failed");

    let (doc2, _) = update_did(
        &doc1,
        &ks,
        UpdateConfig {
            services: None,
            also_known_as: Some(vec!["did:me:alias".into()]),
            hardware_bound: Some(true),
            biometric_protected: None,
            user_verification_method: None,
            device_model: Some("device-x".into()),
            allowed: None,
            threshold: None,
            deactivate: false,
            domain_verification: None,
            rotate_vms: None,
            authentication: None,
            assertion: None,
            invocation: None,
            key_agreement: None,
            created: Some("2025-01-01T00:00:00Z".into()),
        },
    )
    .expect("update_did failed");

    assert_eq!(doc2.also_known_as, vec!["did:me:alias"]);
    assert_eq!(doc2.hardware_bound, Some(true));
    assert_eq!(doc2.device_model, Some("device-x".into()));

    // unchanged fields still preserved
    assert_eq!(doc2.id, doc1.id);
}

#[test]
fn update_can_reassign_core_relationships() {
    let did = "did:me:update-relationships";

    let (doc1, ks) = create_did(
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
        },
        did,
    )
    .expect("create_did failed");

    let (doc2, _) = update_did(
        &doc1,
        &ks,
        UpdateConfig {
            services: None,
            also_known_as: None,
            hardware_bound: None,
            biometric_protected: None,
            user_verification_method: None,
            device_model: None,
            allowed: Some(vec!["#ed25519".into()]),
            threshold: None,
            deactivate: false,
            domain_verification: None,
            rotate_vms: None,
            authentication: Some(vec!["#ed25519".into()]),
            assertion: Some(vec!["#ed25519".into()]),
            invocation: Some(vec!["#ed25519".into()]),
            key_agreement: Some(vec!["#x25519".into(), "#mlkem768".into()]),
            created: None,
        },
    )
    .expect("update_did failed");

    assert_eq!(doc2.authentication, vec!["#ed25519"]);
    assert_eq!(doc2.assertion_method, vec!["#ed25519"]);
    assert_eq!(doc2.key_agreement, vec!["#x25519", "#mlkem768"]);
    assert_eq!(doc2.capability_invocation, vec!["#ed25519"]);
    assert_eq!(
        doc2.update_policy
            .as_ref()
            .map(|policy| policy.allowed_verification_methods.clone()),
        Some(vec!["#ed25519".to_owned()])
    );
}

#[test]
fn set_key_relationships_assigns_existing_methods_without_rotation() {
    let did = "did:me:set-relationships";

    let (doc1, ks1) = create_did(
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
        },
        did,
    )
    .expect("create_did failed");

    let old_public = ks1.get_public("#ed25519").unwrap();

    let (doc2, ks2) = set_key_relationships(
        &doc1,
        &ks1,
        RelationshipAssignmentConfig {
            authentication: Some(vec!["#ed25519".into()]),
            assertion: Some(vec!["#ed25519".into()]),
            invocation: Some(vec!["#ed25519".into()]),
            key_agreement: Some(vec!["#x25519".into(), "#mlkem1024".into()]),
            threshold: None,
            created: None,
        },
    )
    .expect("set relationships failed");

    assert_eq!(doc2.authentication, vec!["#ed25519"]);
    assert_eq!(doc2.assertion_method, vec!["#ed25519"]);
    assert_eq!(doc2.capability_invocation, vec!["#ed25519"]);
    assert_eq!(doc2.key_agreement, vec!["#x25519", "#mlkem1024"]);
    assert_eq!(ks2.get_public("#ed25519").unwrap(), old_public);
}

#[test]
fn set_key_relationships_rejects_duplicate_relationship_refs() {
    let did = "did:me:set-relationships-duplicate";

    let (doc1, ks1) = create_did(
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
        },
        did,
    )
    .expect("create_did failed");

    let err = set_key_relationships(
        &doc1,
        &ks1,
        RelationshipAssignmentConfig {
            authentication: Some(vec!["#ed25519".into(), "#ed25519".into()]),
            assertion: None,
            invocation: None,
            key_agreement: None,
            threshold: None,
            created: None,
        },
    )
    .unwrap_err();

    assert_eq!(err, DidApiError::UpdateRejected);
}

#[test]
fn update_rejects_invocation_that_disagrees_with_allowed_policy() {
    let did = "did:me:update-invocation-mismatch";

    let (doc1, ks) = create_did(
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
        },
        did,
    )
    .expect("create_did failed");

    let err = update_did(
        &doc1,
        &ks,
        UpdateConfig {
            services: None,
            also_known_as: None,
            hardware_bound: None,
            biometric_protected: None,
            user_verification_method: None,
            device_model: None,
            allowed: Some(vec!["#ed25519".into()]),
            threshold: None,
            deactivate: false,
            domain_verification: None,
            rotate_vms: None,
            authentication: None,
            assertion: None,
            invocation: Some(vec!["#x25519".into()]),
            key_agreement: None,
            created: None,
        },
    )
    .unwrap_err();

    assert_eq!(err, DidApiError::RelationshipAssignmentInvalid);
}

#[test]
fn deactivate_did_publishes_terminal_core_shape() {
    let did = "did:me:deactivate";

    let (doc1, ks) = create_did(
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
        },
        did,
    )
    .expect("create_did failed");

    let (doc2, _) = deactivate_did(&doc1, &ks).expect("deactivate_did failed");

    assert_eq!(doc2.id, doc1.id);
    assert_eq!(doc2.sequence, doc1.sequence + 1);
    assert_eq!(doc2.prev, Some(doc1.current_core.clone()));
    assert!(doc2.nonce.is_none());
    assert!(doc2.verification_method.is_empty());
    assert!(doc2.authentication.is_empty());
    assert!(doc2.assertion_method.is_empty());
    assert!(doc2.capability_invocation.is_empty());
    assert!(doc2.key_agreement.is_empty());
    assert!(doc2.service.is_empty());
    assert!(!doc2.attestations.is_empty());

    let policy = doc2.update_policy.as_ref().expect("terminal policy");
    assert!(policy.allowed_verification_methods.is_empty());
    assert!(policy.threshold.is_none());

    let validation = validate_did(
        &doc2,
        DomainVerificationEnv {
            resolve_txt: None,
            fetch_url: None,
        },
    );
    assert!(validation.ok, "{:?}", validation.errors);
}

#[test]
fn deactivate_did_validated_returns_terminal_document_and_validation_result() {
    let did = "did:me:deactivate-validated";

    let (doc1, ks) = create_did(
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
        },
        did,
    )
    .expect("create_did failed");

    let result = deactivate_did_validated(&doc1, &ks).expect("deactivate validation failed");

    assert!(result.validation.ok);
    assert!(result.validation.errors.is_empty());
    assert_eq!(result.document.sequence, doc1.sequence + 1);
    assert!(result.document.verification_method.is_empty());
    assert!(result.keyset.get_public("#ed25519").is_ok());
}

#[test]
fn update_rejects_invalid_old_document() {
    let mut fake = reallyme_did_types::DIDDocument::default();
    fake.id = "".into();

    let ks = KeySet::new();

    let err = update_did(
        &fake,
        &ks,
        UpdateConfig {
            services: None,
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
            created: Some("2025-01-01T00:00:00Z".into()),
        },
    )
    .unwrap_err();

    assert!(
        err.to_string().to_lowercase().contains("invalid"),
        "invalid old document must be rejected"
    );
}
