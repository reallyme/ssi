// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Test coverage for this crate.
#![allow(missing_docs)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::panic)]
#![allow(clippy::expect_used)]

use reallyme_did_core::validate::verification_method::validate_verification_methods;
use reallyme_did_core::validate::{DidValidationCode, DidValidationIssue};
use reallyme_did_types::{Controller, DIDDocument, VerificationMethod};

use reallyme_crypto::core::Algorithm as CryptoAlgorithm;
use reallyme_crypto::dispatch::{generate_keypair, public_key_to_multikey};

/// Helper: build a minimal DIDDocument with given verification methods
fn doc_with_vms(vms: Vec<VerificationMethod>) -> DIDDocument {
    DIDDocument {
        context: vec![
            "https://www.w3.org/ns/did/v1".into(),
            "https://w3id.org/security/multikey/v1".into(),
            "https://did-me.org/ns/did-me/v1".into(),
        ],
        id: "did:me:test".into(),
        controller: Controller::Single("did:me:test".into()),
        also_known_as: vec![],
        sequence: 1,
        prev: None,
        nonce: Some("AAAAAAAAAAAAAAAAAAAAAA".into()),
        core_cbor: "dummy".into(),
        current_core: "dummy".into(),
        key_history: vec![],
        verification_method: vms,
        authentication: vec![],
        assertion_method: vec![],
        capability_invocation: vec![],
        key_agreement: vec![],
        service: vec![],
        update_policy: None,
        domain_verification: vec![],
        attestations: vec![],
        data_integrity_proof: None,
        hardware_bound: None,
        biometric_protected: None,
        user_verification_method: None,
        device_model: None,
        eudi_level_of_assurance: None,
        eudi_schema_version: None,
    }
}

fn has_code(errors: &[DidValidationIssue], code: DidValidationCode) -> bool {
    errors.iter().any(|issue| issue.code == code)
}

#[test]
fn valid_verification_method_passes() {
    let (pubkey, _secret) = generate_keypair(CryptoAlgorithm::Ed25519).unwrap();

    let multibase = public_key_to_multikey(CryptoAlgorithm::Ed25519, &pubkey).unwrap();

    let vm = VerificationMethod {
        id: "#ed25519".into(),
        vm_type: "Multikey".into(),
        controller: "did:me:test".into(),
        algorithm: Some("Ed25519".into()),
        public_key_multibase: multibase,
    };

    let doc = doc_with_vms(vec![vm]);

    let res = validate_verification_methods(&doc);

    assert!(res.ok);
    assert!(res.errors.is_empty());
}

#[test]
fn valid_mlkem768_key_agreement_method_passes() {
    let (pubkey, _secret) = generate_keypair(CryptoAlgorithm::MlKem768).unwrap();

    let multibase = public_key_to_multikey(CryptoAlgorithm::MlKem768, &pubkey).unwrap();

    let vm = VerificationMethod {
        id: "#mlkem768".into(),
        vm_type: "Multikey".into(),
        controller: "did:me:test".into(),
        algorithm: Some("ML-KEM-768".into()),
        public_key_multibase: multibase,
    };

    let mut doc = doc_with_vms(vec![vm]);
    doc.key_agreement = vec!["#mlkem768".into()];

    let res = validate_verification_methods(&doc);

    assert!(res.ok, "{:?}", res.errors);
    assert!(res.errors.is_empty());
}

#[test]
fn duplicate_verification_method_ids_fail() {
    let (pubkey, _) = generate_keypair(CryptoAlgorithm::Ed25519).unwrap();

    let multibase = public_key_to_multikey(CryptoAlgorithm::Ed25519, &pubkey).unwrap();

    let vm1 = VerificationMethod {
        id: "#dup".into(),
        vm_type: "Multikey".into(),
        controller: "did:me:test".into(),
        algorithm: Some("Ed25519".into()),
        public_key_multibase: multibase.clone(),
    };

    let vm2 = VerificationMethod {
        id: "#dup".into(), // duplicate ID
        vm_type: "Multikey".into(),
        controller: "did:me:test".into(),
        algorithm: Some("Ed25519".into()),
        public_key_multibase: multibase,
    };

    let doc = doc_with_vms(vec![vm1, vm2]);

    let res = validate_verification_methods(&doc);

    assert!(!res.ok);
    assert!(has_code(
        &res.errors,
        DidValidationCode::VerificationMethodInvalid
    ));
}

#[test]
fn controller_must_match_did() {
    let (pubkey, _) = generate_keypair(CryptoAlgorithm::Ed25519).unwrap();

    let multibase = public_key_to_multikey(CryptoAlgorithm::Ed25519, &pubkey).unwrap();

    let vm = VerificationMethod {
        id: "#bad-controller".into(),
        vm_type: "Multikey".into(),
        controller: "did:me:other".into(), // WRONG
        algorithm: Some("Ed25519".into()),
        public_key_multibase: multibase,
    };

    let doc = doc_with_vms(vec![vm]);

    let res = validate_verification_methods(&doc);

    assert!(!res.ok);
    assert!(has_code(
        &res.errors,
        DidValidationCode::VerificationMethodInvalid
    ));
}

#[test]
fn invalid_multibase_fails() {
    let vm = VerificationMethod {
        id: "#invalid".into(),
        vm_type: "Multikey".into(),
        controller: "did:me:test".into(),
        algorithm: Some("Ed25519".into()),
        public_key_multibase: "zINVALIDMULTIKEY".into(),
    };

    let doc = doc_with_vms(vec![vm]);

    let res = validate_verification_methods(&doc);

    assert!(!res.ok);
    assert!(has_code(
        &res.errors,
        DidValidationCode::VerificationMethodInvalid
    ));
}

#[test]
fn algorithm_mismatch_with_multikey_fails() {
    let (pubkey, _) = generate_keypair(CryptoAlgorithm::Ed25519).unwrap();

    let multibase = public_key_to_multikey(CryptoAlgorithm::Ed25519, &pubkey).unwrap();

    let vm = VerificationMethod {
        id: "#alg-mismatch".into(),
        vm_type: "Multikey".into(),
        controller: "did:me:test".into(),
        algorithm: Some("secp256k1".into()), // WRONG
        public_key_multibase: multibase,
    };

    let doc = doc_with_vms(vec![vm]);

    let res = validate_verification_methods(&doc);

    assert!(!res.ok);
    assert!(has_code(
        &res.errors,
        DidValidationCode::VerificationMethodInvalid
    ));
}

#[test]
fn missing_algorithm_fails() {
    let (pubkey, _) = generate_keypair(CryptoAlgorithm::Ed25519).unwrap();

    let multibase = public_key_to_multikey(CryptoAlgorithm::Ed25519, &pubkey).unwrap();

    let vm = VerificationMethod {
        id: "#no-alg".into(),
        vm_type: "Multikey".into(),
        controller: "did:me:test".into(),
        algorithm: None,
        public_key_multibase: multibase,
    };

    let doc = doc_with_vms(vec![vm]);

    let res = validate_verification_methods(&doc);

    assert!(!res.ok);
    assert!(has_code(
        &res.errors,
        DidValidationCode::VerificationMethodInvalid
    ));
}
