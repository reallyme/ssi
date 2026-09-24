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
    rotate::{
        replace_compromised_keys, rotate_all_keys, rotate_keys, rotate_relationship_keys,
        RekeyRelationship,
    },
    update::{update_did, UpdateConfig},
    validate::{validate_did, DomainVerificationEnv},
    CreateConfig,
};

/// ------------------------------------------------------------
/// Rotation without Data Integrity Proof (Messaging profile)
/// ------------------------------------------------------------

#[test]
fn rotate_single_key_changes_public_key_without_di_proof() {
    let did = "did:me:rotate-one";

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

            // Messaging profile has NO DI proof
            created: None,
        },
        did,
    )
    .expect("create_did failed");

    assert!(doc1.data_integrity_proof.is_none());

    let old_pub = ks1.get_public("#ed25519").unwrap();

    let (doc2, ks2) = rotate_keys(
        &doc1,
        &ks1,
        &["#ed25519".into()],
        None, // 👈 no DI proof regeneration
    )
    .expect("rotate_keys failed");

    let new_pub = ks2.get_public("#ed25519").unwrap();

    assert_ne!(old_pub, new_pub, "rotated key must change");
    assert_eq!(doc2.sequence, doc1.sequence + 1);
    assert_eq!(doc2.prev, Some(doc1.current_core.clone()));
    assert!(doc2.data_integrity_proof.is_none());

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
fn rotate_preserves_unrotated_keys_without_di_proof() {
    let did = "did:me:rotate-preserve";

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

    let x25519_before = ks1.get_public("#x25519").unwrap();

    let (_, ks2) =
        rotate_keys(&doc1, &ks1, &["#ed25519".into()], None).expect("rotate_keys failed");

    assert_eq!(
        x25519_before,
        ks2.get_public("#x25519").unwrap(),
        "unrotated keys must remain unchanged"
    );
}

#[test]
fn rotate_relationship_keys_rekeys_key_agreement_methods() {
    let did = "did:me:rotate-key-agreement";

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

    let old_ed = ks1.get_public("#ed25519").unwrap();
    let old_x25519 = ks1.get_public("#x25519").unwrap();
    let old_mlkem768 = ks1.get_public("#mlkem768").unwrap();
    let old_mlkem1024 = ks1.get_public("#mlkem1024").unwrap();

    let (doc2, ks2) = rotate_relationship_keys(&doc1, &ks1, RekeyRelationship::KeyAgreement, None)
        .expect("relationship rekey failed");

    assert_eq!(doc2.sequence, doc1.sequence + 1);
    assert_eq!(ks2.get_public("#ed25519").unwrap(), old_ed);
    assert_ne!(ks2.get_public("#x25519").unwrap(), old_x25519);
    assert_ne!(ks2.get_public("#mlkem768").unwrap(), old_mlkem768);
    assert_ne!(ks2.get_public("#mlkem1024").unwrap(), old_mlkem1024);
}

#[test]
fn relationship_rotation_fails_closed_for_unsupported_did_core_relationships() {
    let did = "did:me:rotate-unsupported-relationship";

    let (doc, ks) = create_did(
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

    let err = rotate_relationship_keys(&doc, &ks, RekeyRelationship::CapabilityDelegation, None)
        .unwrap_err();

    assert_eq!(err, DidApiError::UnsupportedDidRelationship);
}

#[test]
fn rotate_all_keys_rekeys_every_verification_method() {
    let did = "did:me:rotate-all";

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

    let before: Vec<(String, String)> = doc1
        .verification_method
        .iter()
        .map(|vm| (vm.id.clone(), ks1.get_public(&vm.id).unwrap()))
        .collect();

    let (doc2, ks2) = rotate_all_keys(&doc1, &ks1, None).expect("all-key rekey failed");

    assert_eq!(doc2.sequence, doc1.sequence + 1);
    for (id, old_public) in before {
        assert_ne!(ks2.get_public(&id).unwrap(), old_public, "{id} must rekey");
    }
}

#[test]
fn replace_compromised_keys_rekeys_non_authority_method() {
    let did = "did:me:replace-compromised";

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

    let old_public = ks1.get_public("#x25519").unwrap();

    let (doc2, ks2) = replace_compromised_keys(&doc1, &ks1, &["#x25519".into()], None)
        .expect("compromise recovery failed");

    assert_eq!(doc2.sequence, doc1.sequence + 1);
    assert_eq!(doc2.prev, Some(doc1.current_core.clone()));
    assert_ne!(ks2.get_public("#x25519").unwrap(), old_public);
}

#[test]
fn replace_compromised_keys_rejects_compromised_sole_update_authority() {
    let did = "did:me:replace-compromised-sole-authority";

    let (doc, ks) = create_did(
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

    let err = replace_compromised_keys(&doc, &ks, &["#ed25519".into()], None).unwrap_err();

    assert_eq!(err, DidApiError::PolicyViolation);
}

#[test]
fn replace_compromised_keys_uses_remaining_update_authority() {
    let did = "did:me:replace-compromised-with-backup";

    let (doc1, ks1) = create_did(
        CreateConfig {
            profile: Some(DidProfile::CoreIdentity),
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
            allowed: Some(vec!["#mldsa87-root".into(), "#ed25519".into()]),
            threshold: Some(1),
            deactivate: false,
            domain_verification: None,
            rotate_vms: None,
            authentication: None,
            assertion: None,
            invocation: Some(vec!["#mldsa87-root".into(), "#ed25519".into()]),
            key_agreement: None,
            created: Some("2025-01-02T00:00:00Z".into()),
        },
    )
    .expect("policy preparation failed");

    let old_public = ks2.get_public("#ed25519").unwrap();

    let (doc3, ks3) = replace_compromised_keys(
        &doc2,
        &ks2,
        &["#ed25519".into()],
        Some("2025-01-03T00:00:00Z".into()),
    )
    .expect("compromise recovery failed");

    assert_ne!(ks3.get_public("#ed25519").unwrap(), old_public);
    assert!(doc3
        .attestations
        .iter()
        .any(|attestation| attestation.vm == "#mldsa87-root"));
    assert!(!doc3
        .attestations
        .iter()
        .any(|attestation| attestation.vm == "#ed25519"));
}

#[test]
fn rotate_keys_rejects_empty_explicit_selection() {
    let did = "did:me:rotate-empty";

    let (doc, ks) = create_did(
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

    let err = rotate_keys(&doc, &ks, &[], None).unwrap_err();

    assert_eq!(err, DidApiError::VerificationMethodSelectionRequired);
}

#[test]
fn rotate_fails_for_unknown_vm() {
    let did = "did:me:rotate-invalid";

    let (doc, ks) = create_did(
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

    let err = rotate_keys(&doc, &ks, &["#does-not-exist".into()], None).unwrap_err();

    assert!(
        err.to_string().contains("not found"),
        "rotation must fail for unknown VM"
    );
}

/// ------------------------------------------------------------
/// Rotation WITH Data Integrity Proof (CoreIdentity profile)
/// ------------------------------------------------------------

#[test]
fn rotate_multiple_keys_regenerates_di_proof() {
    let did = "did:me:rotate-many";

    // CoreIdentity profile → DI proof exists
    let (doc1, ks1) = create_did(
        CreateConfig {
            profile: Some(DidProfile::CoreIdentity),
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

            // Required to create initial DI proof
            created: Some("2025-01-01T00:00:00Z".into()),
        },
        did,
    )
    .expect("create_did failed");

    assert!(
        doc1.data_integrity_proof.is_some(),
        "CoreIdentity must start with a DI proof"
    );

    let old_ed = ks1.get_public("#ed25519").unwrap();
    let old_root = ks1.get_public("#mldsa87-root").unwrap();

    // Rotation MUST regenerate DI proof → created REQUIRED
    let (doc2, ks2) = rotate_keys(
        &doc1,
        &ks1,
        &["#ed25519".into(), "#mldsa87-root".into()],
        Some("2025-01-02T00:00:00Z".into()), // 👈 regeneration timestamp
    )
    .expect("rotate_keys failed");

    assert_ne!(old_ed, ks2.get_public("#ed25519").unwrap());
    assert_ne!(old_root, ks2.get_public("#mldsa87-root").unwrap());

    assert!(
        doc2.data_integrity_proof.is_some(),
        "DI proof must be regenerated on rotation"
    );

    // Proof must be different (new CID, new signature)
    assert_ne!(
        doc1.data_integrity_proof
            .as_ref()
            .and_then(|proof| proof.jws.as_ref()),
        doc2.data_integrity_proof
            .as_ref()
            .and_then(|proof| proof.jws.as_ref()),
        "DI proof must change after rotation"
    );
}
