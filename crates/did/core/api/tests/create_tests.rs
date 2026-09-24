// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Test coverage for this crate.
#![allow(missing_docs)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::panic)]
#![allow(clippy::expect_used)]

use identity_core_primitives::Algorithm;
use reallyme_did_api::{create::create_did, CreateConfig, DidApiError, DidProfile, KeySet};

fn core_identity_config() -> CreateConfig {
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
    }
}

#[test]
fn create_did_from_core_identity_profile() {
    let cfg = core_identity_config();

    let did = "did:me:test";

    let (doc, ks) = create_did(cfg, did).expect("create_did failed");

    // --- DID basics ---
    assert!(doc.id.starts_with("did:me:me1"));
    assert_ne!(doc.id, did);
    assert_eq!(doc.sequence, 1);

    // current_core MUST be present and non-empty
    assert!(!doc.current_core.is_empty());

    // --- verification methods present ---
    let vm_ids: Vec<&str> = doc
        .verification_method
        .iter()
        .map(|v| v.id.as_str())
        .collect();

    assert!(vm_ids.contains(&"#ed25519"));
    assert!(vm_ids.contains(&"#mldsa87-root"));
    assert!(vm_ids.contains(&"#x25519"));

    // --- keyset populated ---
    assert!(!ks.get_private("#ed25519").unwrap().is_empty());
    assert!(!ks.get_public("#ed25519").unwrap().is_empty());

    // --- core signatures present ---
    assert!(!doc.attestations.is_empty());
}

#[test]
fn omitted_profile_uses_default_interoperability_profile() {
    let mut cfg = core_identity_config();
    cfg.profile = None;

    let (document, key_set) =
        create_did(cfg, "did:me:default-profile").expect("default creation failed");

    for verification_method in [
        "#ed25519",
        "#mldsa87-auth",
        "#p256",
        "#mldsa87-root",
        "#x25519",
        "#mlkem768",
    ] {
        assert!(document
            .verification_method
            .iter()
            .any(|method| method.id == verification_method));
        assert!(key_set.get_private(verification_method).is_ok());
    }

    assert!(document
        .authentication
        .iter()
        .any(|reference| reference == "#ed25519"));
    assert!(document
        .authentication
        .iter()
        .any(|reference| reference == "#mldsa87-auth"));
    assert!(document
        .assertion_method
        .iter()
        .any(|reference| reference == "#p256"));
    assert!(document
        .capability_invocation
        .iter()
        .any(|reference| reference == "#mldsa87-root"));
    assert!(document
        .key_agreement
        .iter()
        .any(|reference| reference == "#x25519"));
    assert!(document
        .key_agreement
        .iter()
        .any(|reference| reference == "#mlkem768"));
    let Some(update_policy) = document.update_policy.as_ref() else {
        panic!("the default profile must include an update policy");
    };
    assert_eq!(update_policy.threshold, Some(2));
    assert!(update_policy
        .allowed_verification_methods
        .iter()
        .any(|reference| reference == "#mldsa87-root"));
    assert!(!document.attestations.is_empty());
}

#[test]
fn manual_relationships_without_verification_methods_are_rejected() {
    let mut cfg = core_identity_config();
    cfg.profile = None;
    cfg.verification_methods = None;
    cfg.authentication = Some(vec!["#unknown".into()]);

    let outcome = create_did(cfg, "did:me:invalid-manual-configuration");

    assert!(matches!(
        outcome,
        Err(DidApiError::MissingVerificationMethods)
    ));
}

#[test]
fn created_pq_did_keys_round_trip_through_reallyme_cose_profile() {
    use reallyme_cose::{
        cose_decrypt_ml_kem, cose_encrypt_ml_kem_direct, cose_encrypt_ml_kem_key_wrap,
        cose_key_to_public_bytes, cose_sign1, cose_verify1, derive_kid_from_cose_key_public,
        multikey_to_cose_key, CoseContentEncryptionAlgorithm, CoseMlKemAlgorithm,
        CoseMlKemDecryptRequest, CoseMlKemEncryptRequest,
    };
    use reallyme_crypto::core::Algorithm;

    const PLAINTEXT: &[u8] = b"ReallyMe Identity PQ DID to COSE integration";
    const SUPP_PRIV_INFO: &[u8] = b"reallyme-identity-pq-did-v1";

    let (document, key_set) = create_did(core_identity_config(), "did:me:pq-cose").unwrap();

    let signing_method = document
        .verification_method
        .iter()
        .find(|method| method.id == "#mldsa87-root")
        .unwrap();
    assert!(document
        .capability_invocation
        .iter()
        .any(|reference| reference == "#mldsa87-root"));
    let signing_cose_key = multikey_to_cose_key(&signing_method.public_key_multibase).unwrap();
    let signing_public_key = cose_key_to_public_bytes(&signing_cose_key).unwrap();
    let signing_kid = derive_kid_from_cose_key_public(&signing_cose_key).unwrap();
    let signing_private_key = key_set.private_key("#mldsa87-root").unwrap();
    let signed = cose_sign1(
        Algorithm::MlDsa87,
        PLAINTEXT,
        signing_private_key.expose_secret(),
        Some(&signing_kid),
    )
    .unwrap();
    let verified = cose_verify1(&signed, |algorithm, candidate_kid| {
        if algorithm == Algorithm::MlDsa87 && candidate_kid == signing_kid.as_slice() {
            Some(signing_public_key.clone())
        } else {
            None
        }
    })
    .unwrap();
    assert_eq!(verified.as_slice(), PLAINTEXT);

    for (verification_method_id, cose_algorithm) in [
        ("#mlkem768", CoseMlKemAlgorithm::MlKem768),
        ("#mlkem1024", CoseMlKemAlgorithm::MlKem1024),
    ] {
        assert!(document
            .key_agreement
            .iter()
            .any(|reference| reference == verification_method_id));
        let verification_method = document
            .verification_method
            .iter()
            .find(|method| method.id == verification_method_id)
            .unwrap();
        assert_eq!(
            verification_method.public_key_multibase,
            key_set.public_key(verification_method_id).unwrap()
        );

        let cose_key = multikey_to_cose_key(&verification_method.public_key_multibase).unwrap();
        let public_key = cose_key_to_public_bytes(&cose_key).unwrap();
        let kid = derive_kid_from_cose_key_public(&cose_key).unwrap();
        let private_key = key_set.private_key(verification_method_id).unwrap();
        let request = CoseMlKemEncryptRequest::new(
            cose_algorithm,
            CoseContentEncryptionAlgorithm::Aes256Gcm,
            &public_key,
            &kid,
            PLAINTEXT,
            Some(SUPP_PRIV_INFO),
        );

        for encrypted in [
            cose_encrypt_ml_kem_direct(&request).unwrap(),
            cose_encrypt_ml_kem_key_wrap(&request).unwrap(),
        ] {
            let decrypt_request = CoseMlKemDecryptRequest::new(
                &encrypted,
                private_key.expose_secret(),
                &kid,
                Some(SUPP_PRIV_INFO),
            );
            let decrypted = cose_decrypt_ml_kem(&decrypt_request).unwrap();

            assert_eq!(decrypted.plaintext.as_slice(), PLAINTEXT);
            assert_eq!(decrypted.kid.as_slice(), kid.as_slice());
        }
    }
}

#[test]
fn create_did_with_manual_verification_methods() {
    let cfg = CreateConfig {
        profile: None,
        also_known_as: None,
        hardware_bound: None,
        biometric_protected: None,
        user_verification_method: None,
        device_model: None,
        services: None,
        update_policy: None,
        domain_verification: None,

        verification_methods: Some(vec![
            ("#ed".into(), Algorithm::Ed25519),
            ("#x".into(), Algorithm::X25519),
        ]),
        authentication: None,
        assertion: None,
        invocation: None,
        key_agreement: None,
        created: Some("2025-01-01T00:00:00Z".into()),
    };

    let did = "did:me:manual";

    let (doc, ks) = create_did(cfg, did).expect("create_did failed");

    let vm_ids: Vec<&str> = doc
        .verification_method
        .iter()
        .map(|v| v.id.as_str())
        .collect();

    assert_eq!(vm_ids, vec!["#ed", "#x"]);

    assert!(!ks.get_private("#ed").unwrap().is_empty());
    assert!(!ks.get_public("#x").unwrap().is_empty());

    // current_core MUST exist
    assert!(!doc.current_core.is_empty());
}

#[test]
fn missing_private_key_does_not_sign() {
    let mut ks = KeySet::new();
    ks.put_public("#k1", "z6MkkRtoB8oeJhJGp6WT8PAzmNmcAA4UDCmMiHHnPKDo9jJ3")
        .unwrap();

    let k = ks.get_private("#k1");
    assert!(k.is_err());
}
