// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Test coverage for this crate.
#![allow(missing_docs)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::panic)]
#![allow(clippy::expect_used)]

use identity_core_primitives::Algorithm;
use reallyme_codec::base64url::bytes_to_base64url;
use reallyme_did_core::validate::{
    validate_did_document, DidValidationCode, DidValidationIssue, DomainVerificationEnv,
};
use reallyme_did_core::{sign_core, Canonical, CoreVerificationMethod, DidCore, UpdatePolicy};
use reallyme_did_types::{Controller, DIDDocument, DataIntegrityProof, VerificationMethod};

fn has_code(errors: &[DidValidationIssue], code: DidValidationCode) -> bool {
    errors.iter().any(|issue| issue.code == code)
}

/// Build a minimal valid DIDDocument + core snapshot
fn make_valid_doc() -> DIDDocument {
    use reallyme_crypto::core::Algorithm as CryptoAlgorithm;
    use reallyme_crypto::dispatch::{generate_keypair, public_key_to_multikey};

    // --------------------------------------------------
    // 1. Generate a real Ed25519 keypair
    // --------------------------------------------------
    let (public, secret) = generate_keypair(CryptoAlgorithm::Ed25519).unwrap();

    let multikey = public_key_to_multikey(CryptoAlgorithm::Ed25519, &public).unwrap();

    // --------------------------------------------------
    // 2. Build core
    // --------------------------------------------------
    let nonce = vec![0; 16];
    let update_policy = UpdatePolicy {
        allowed_verification_methods: vec!["#k1".into()],
        threshold: None,
    };
    let controller_keys = vec![CoreVerificationMethod {
        id: "#k1".into(),
        vm_type: "Multikey".into(),
        algorithm: Algorithm::Ed25519,
        public_key_multibase: multikey.clone(),
    }];
    let did = "did:me:test".to_owned();

    let core = DidCore {
        id: did.clone(),
        sequence: 1,
        nonce: Some(nonce),
        controller: vec![did.clone()],
        controller_keys,
        authentication: vec!["#k1".into()],
        assertion: vec![],
        key_agreement: vec![],
        services: vec![],
        update_policy,
        prev: None,
    };

    let core_cbor = core.canonical_cbor().unwrap();
    let core_cid = reallyme_did_core::compute_core_cid(&core).unwrap();
    let core_attestations = sign_core(&core, &core.controller_keys, &["#k1".into()], |id| {
        if id == "#k1" {
            Some(secret.to_vec())
        } else {
            None
        }
    })
    .unwrap();
    let attestations = core_attestations
        .into_iter()
        .map(|a| reallyme_did_types::Attestation {
            alg: a.algorithm,
            vm: a.verification_method,
            sig: a.signature,
        })
        .collect();

    // --------------------------------------------------
    // 3. Build DID Document projection
    // --------------------------------------------------
    DIDDocument {
        context: vec![
            "https://www.w3.org/ns/did/v1".into(),
            "https://w3id.org/security/multikey/v1".into(),
            "https://did-me.org/ns/did-me/v1".into(),
        ],
        id: did.clone(),
        controller: Controller::Single(did.clone()),
        sequence: 1,
        prev: None,
        nonce: Some("AAAAAAAAAAAAAAAAAAAAAA".into()),
        core_cbor: bytes_to_base64url(&core_cbor),
        current_core: core_cid,
        key_history: vec![],

        verification_method: vec![VerificationMethod {
            id: "#k1".into(),
            vm_type: "Multikey".into(),
            controller: did,
            algorithm: Some("Ed25519".into()),
            public_key_multibase: multikey,
        }],

        authentication: vec!["#k1".into()],
        assertion_method: vec![],
        capability_invocation: vec!["#k1".into()],
        key_agreement: vec![],
        service: vec![],

        update_policy: Some(reallyme_did_types::UpdatePolicy {
            allowed_verification_methods: vec!["#k1".into()],
            threshold: None,
        }),

        attestations,
        data_integrity_proof: None,
        also_known_as: vec![],
        hardware_bound: None,
        biometric_protected: None,
        user_verification_method: None,
        eudi_level_of_assurance: None,
        eudi_schema_version: None,
        device_model: None,
        domain_verification: vec![],
    }
}

#[test]
fn valid_document_passes_full_validation() {
    let doc = make_valid_doc();

    let env = DomainVerificationEnv {
        resolve_txt: None,
        fetch_url: None,
    };

    let res = validate_did_document(&doc, env);

    assert!(res.ok, "{:?}", res.errors);
    assert!(res.errors.is_empty());
    assert!(res.warnings.is_empty());
    assert!(res.core.is_some());
}

#[test]
fn optional_data_integrity_proof_issue_is_non_fatal_to_did_validity() {
    let mut doc = make_valid_doc();
    doc.data_integrity_proof = Some(DataIntegrityProof {
        proof_type: "WrongProofType".into(),
        cryptosuite: Some("unsupported-suite".into()),
        proof_purpose: Some("assertionMethod".into()),
        verification_method: Some("#p256".into()),
        created: Some("2026-01-01T00:00:00Z".into()),
        jws: Some("a.b.c".into()),
    });

    let res = validate_did_document(
        &doc,
        DomainVerificationEnv {
            resolve_txt: None,
            fetch_url: None,
        },
    );

    assert!(res.ok, "{:?}", res.errors);
    assert!(res.errors.is_empty());
    assert!(has_code(
        &res.warnings,
        DidValidationCode::DataIntegrityProofInvalid
    ));
}

#[test]
fn structural_error_short_circuits_validation() {
    let mut doc = make_valid_doc();
    doc.id = "".into(); // invalid DID

    let res = validate_did_document(
        &doc,
        DomainVerificationEnv {
            resolve_txt: None,
            fetch_url: None,
        },
    );

    assert!(!res.ok);
    assert!(
        res.core.is_none(),
        "core must not be decoded on structural failure"
    );
}

#[test]
fn core_validation_error_is_reported() {
    let mut doc = make_valid_doc();
    doc.current_core = "bafyINVALID".into();

    let res = validate_did_document(
        &doc,
        DomainVerificationEnv {
            resolve_txt: None,
            fetch_url: None,
        },
    );

    assert!(!res.ok);
    assert!(has_code(&res.errors, DidValidationCode::CoreCidMismatch));
}

#[test]
fn domain_verification_failure_is_reported() {
    let mut doc = make_valid_doc();

    doc.domain_verification
        .push(reallyme_did_types::DomainVerification {
            verification_type: "DnsTxtVerification".into(),
            method: "dns".into(),
            domain: "example.com".into(),
            dns: Some(reallyme_did_types::DNSBinding {
                record_name: "_did".into(),
                txt_value: "did:me:test".into(),
            }),
            wellknown: None,
        });

    let env = DomainVerificationEnv {
        resolve_txt: Some(&|_domain| Ok(vec!["did:me:OTHER".into()])),
        fetch_url: None,
    };

    let res = validate_did_document(&doc, env);

    assert!(!res.ok);
    assert!(
        has_code(&res.errors, DidValidationCode::DomainVerificationFailed),
        "{:?}",
        res.errors
    );
}

#[test]
fn verification_method_semantic_error_is_reported() {
    let mut doc = make_valid_doc();

    doc.verification_method.push(VerificationMethod {
        id: "#k1".into(),
        vm_type: "Multikey".into(),
        controller: "did:me:OTHER".into(), // invalid controller
        algorithm: Some("Ed25519".into()),
        public_key_multibase: "zInvalid".into(),
    });

    let res = validate_did_document(
        &doc,
        DomainVerificationEnv {
            resolve_txt: None,
            fetch_url: None,
        },
    );

    assert!(!res.ok);
    assert!(
        has_code(&res.errors, DidValidationCode::CoreProjectionMismatch)
            || has_code(&res.errors, DidValidationCode::VerificationMethodInvalid),
        "{:?}",
        res.errors
    );
}
