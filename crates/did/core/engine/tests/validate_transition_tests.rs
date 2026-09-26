// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Regression coverage for core-bound attestation authority and update transitions.
#![allow(missing_docs)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::panic)]
#![allow(clippy::expect_used)]

use std::cell::Cell;
use std::collections::HashMap;

use identity_core_primitives::Algorithm;
use reallyme_codec::base64url::{base64url_to_bytes, bytes_to_base64url};
use reallyme_crypto::core::Algorithm as CryptoAlgorithm;
use reallyme_crypto::dispatch::{generate_keypair, public_key_to_multikey, sign};
use reallyme_did_core::error::DidCoreError;
use reallyme_did_core::validate::limits::MAX_VERIFICATION_METHODS;
use reallyme_did_core::validate::{
    validate_did_document, validate_did_document_consistency, validate_did_document_transition,
    validate_domain_entry, DidDocumentViewForDV, DidValidationCode, DidValidationIssue,
    DomainVerificationEnv, DomainVerificationError,
};
use reallyme_did_core::{
    core_signature_input, sign_core, update_engine, Canonical, CoreVerificationMethod, DidCore,
    UpdateMetadata, UpdateOptions, UpdatePolicy, UpdateRelationships,
};
use reallyme_did_types::{
    Controller, DIDDocument, DNSBinding, DomainVerification, VerificationMethod, WellKnownBinding,
};

const DID: &str = "did:me:test";

struct Keypair {
    secret: Vec<u8>,
    multikey: String,
}

fn ed25519() -> Keypair {
    let (public, secret) = generate_keypair(CryptoAlgorithm::Ed25519).unwrap();
    let multikey = public_key_to_multikey(CryptoAlgorithm::Ed25519, &public).unwrap();
    Keypair {
        secret: secret.to_vec(),
        multikey,
    }
}

fn no_env() -> DomainVerificationEnv<'static> {
    DomainVerificationEnv {
        resolve_txt: None,
        fetch_url: None,
    }
}

fn has_code(errors: &[DidValidationIssue], code: DidValidationCode) -> bool {
    errors.iter().any(|issue| issue.code == code)
}

fn genesis(key: &Keypair) -> DIDDocument {
    let update_policy = UpdatePolicy {
        allowed_verification_methods: vec!["#k1".into()],
        threshold: None,
    };
    let core = DidCore {
        id: DID.into(),
        sequence: 1,
        nonce: Some(vec![0; 16]),
        controller: vec![DID.into()],
        controller_keys: vec![CoreVerificationMethod {
            id: "#k1".into(),
            vm_type: "Multikey".into(),
            algorithm: Algorithm::Ed25519,
            public_key_multibase: key.multikey.clone(),
        }],
        authentication: vec!["#k1".into()],
        assertion: vec![],
        key_agreement: vec![],
        services: vec![],
        update_policy,
        prev: None,
    };
    let core_cbor = core.canonical_cbor().unwrap();
    let attestations = sign_core(&core, &core.controller_keys, &["#k1".into()], |id| {
        (id == "#k1").then(|| key.secret.clone())
    })
    .unwrap()
    .into_iter()
    .map(|a| reallyme_did_types::Attestation {
        alg: a.algorithm,
        vm: a.verification_method,
        sig: a.signature,
    })
    .collect();

    DIDDocument {
        context: vec![
            "https://www.w3.org/ns/did/v1".into(),
            "https://w3id.org/security/multikey/v1".into(),
            "https://did-me.org/ns/did-me/v1".into(),
        ],
        id: DID.into(),
        controller: Controller::Single(DID.into()),
        sequence: 1,
        prev: None,
        nonce: Some("AAAAAAAAAAAAAAAAAAAAAA".into()),
        core_cbor: bytes_to_base64url(&core_cbor),
        current_core: reallyme_did_core::compute_core_cid(&core).unwrap(),
        key_history: vec![],
        verification_method: vec![VerificationMethod {
            id: "#k1".into(),
            vm_type: "Multikey".into(),
            controller: DID.into(),
            algorithm: Some("Ed25519".into()),
            public_key_multibase: key.multikey.clone(),
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

/// Produce the next document with the update engine.
///
/// `authorization_secret` signs the new core for `#k1`; `rotated` optionally
/// replaces `#k1`'s public key in the new core.
fn next_document(
    old: &DIDDocument,
    authorization_secret: &[u8],
    rotated: Option<&str>,
    deactivate: bool,
) -> DIDDocument {
    let mut rotate = HashMap::new();
    if rotated.is_some() {
        rotate.insert("#k1".to_owned(), true);
    }
    let options = UpdateOptions {
        old,
        rotate,
        allowed: if deactivate {
            vec![]
        } else {
            vec!["#k1".into()]
        },
        threshold: None,
        deactivate,
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
    };
    update_engine(
        options,
        |id| (id == "#k1").then(|| authorization_secret.to_vec()),
        |_| None,
        |id| {
            if id == "#k1" {
                rotated.map(str::to_owned)
            } else {
                None
            }
        },
    )
    .expect("update engine must produce the next document")
}

/// A copy of `doc` whose unsigned JSON projection advertises `attacker` for `#k1`.
fn with_projected_key(doc: &DIDDocument, attacker: &Keypair) -> DIDDocument {
    let mut forged = doc.clone();
    forged.verification_method[0].public_key_multibase = attacker.multikey.clone();
    forged
}

// -----------------------------------------------------------------------------
// C1: JSON verification methods must be bound to the signed core
// -----------------------------------------------------------------------------

#[test]
fn swapped_projection_key_with_resigned_attestation_is_rejected() {
    let owner = ed25519();
    let attacker = ed25519();
    let mut forged = with_projected_key(&genesis(&owner), &attacker);

    // Re-sign the unchanged core bytes with the attacker's key.
    let core_bytes = base64url_to_bytes(&forged.core_cbor).unwrap();
    let signing_input = core_signature_input(&core_bytes).unwrap();
    let signature = sign(CryptoAlgorithm::Ed25519, &attacker.secret, &signing_input).unwrap();
    forged.attestations[0].sig = bytes_to_base64url(&signature);

    let result = validate_did_document(&forged, no_env());

    assert!(!result.ok);
    assert!(has_code(
        &result.errors,
        DidValidationCode::CoreProjectionMismatch
    ));
    assert!(has_code(
        &result.errors,
        DidValidationCode::AttestationSignatureInvalid
    ));
}

#[test]
fn projection_key_type_and_algorithm_must_match_core() {
    let owner = ed25519();
    let mut forged = genesis(&owner);
    forged.verification_method[0].algorithm = Some("secp256k1".into());

    let result = validate_did_document(&forged, no_env());

    assert!(!result.ok);
    assert!(has_code(
        &result.errors,
        DidValidationCode::CoreProjectionMismatch
    ));
}

// -----------------------------------------------------------------------------
// H1: non-genesis documents are authorized by the previous core state
// -----------------------------------------------------------------------------

#[test]
fn successor_is_never_valid_without_previous_state() {
    let key = ed25519();
    let doc1 = genesis(&key);
    let doc2 = next_document(&doc1, &key.secret, None, false);

    let standalone = validate_did_document(&doc2, no_env());
    assert!(!standalone.ok);
    assert!(has_code(
        &standalone.errors,
        DidValidationCode::TransitionAuthorityUnverified
    ));

    let consistency = validate_did_document_consistency(&doc2, no_env());
    assert!(consistency.ok, "{:?}", consistency.errors);
    assert!(has_code(
        &consistency.warnings,
        DidValidationCode::TransitionAuthorityUnverified
    ));
}

#[test]
fn rotation_is_authorized_by_previous_keys_across_a_chain() {
    let key1 = ed25519();
    let key2 = ed25519();
    let doc1 = genesis(&key1);
    assert!(validate_did_document(&doc1, no_env()).ok);

    let doc2 = next_document(&doc1, &key1.secret, Some(&key2.multikey), false);
    let step = validate_did_document_transition(&doc1, &doc2, no_env());
    assert!(step.ok, "{:?}", step.errors);

    // The rotated key now holds update authority for the following step.
    let doc3 = next_document(&doc2, &key2.secret, None, false);
    let step = validate_did_document_transition(&doc2, &doc3, no_env());
    assert!(step.ok, "{:?}", step.errors);

    // ...and the superseded key no longer does.
    let stale = next_document(&doc2, &key1.secret, None, false);
    let step = validate_did_document_transition(&doc2, &stale, no_env());
    assert!(!step.ok);
    assert!(has_code(
        &step.errors,
        DidValidationCode::AttestationSignatureInvalid
    ));
}

#[test]
fn successor_signed_by_replacement_key_is_rejected() {
    let key1 = ed25519();
    let key2 = ed25519();
    let doc1 = genesis(&key1);
    let doc2 = next_document(&doc1, &key2.secret, Some(&key2.multikey), false);

    let step = validate_did_document_transition(&doc1, &doc2, no_env());

    assert!(!step.ok);
    assert!(has_code(
        &step.errors,
        DidValidationCode::AttestationSignatureInvalid
    ));
}

#[test]
fn forged_successor_with_attacker_authority_is_rejected() {
    let owner = ed25519();
    let attacker = ed25519();
    let doc1 = genesis(&owner);
    // The attacker extends the real head, but signs with keys it controls.
    let forged_base = with_projected_key(&doc1, &attacker);
    let forged = next_document(&forged_base, &attacker.secret, None, false);
    assert_eq!(forged.prev.as_deref(), Some(doc1.current_core.as_str()));

    let step = validate_did_document_transition(&doc1, &forged, no_env());

    assert!(!step.ok);
    assert!(has_code(
        &step.errors,
        DidValidationCode::AttestationSignatureInvalid
    ));
}

#[test]
fn forged_terminal_deactivation_requires_previous_authority() {
    let owner = ed25519();
    let attacker = ed25519();
    let doc1 = genesis(&owner);

    let legitimate = next_document(&doc1, &owner.secret, None, true);
    let step = validate_did_document_transition(&doc1, &legitimate, no_env());
    assert!(step.ok, "{:?}", step.errors);
    assert!(!validate_did_document(&legitimate, no_env()).ok);

    let forged = next_document(
        &with_projected_key(&doc1, &attacker),
        &attacker.secret,
        None,
        true,
    );
    let step = validate_did_document_transition(&doc1, &forged, no_env());
    assert!(!step.ok);
    assert!(has_code(
        &step.errors,
        DidValidationCode::AttestationSignatureInvalid
    ));

    let mut unsigned = legitimate.clone();
    unsigned.attestations.clear();
    let step = validate_did_document_transition(&doc1, &unsigned, no_env());
    assert!(!step.ok);
    assert!(has_code(
        &step.errors,
        DidValidationCode::AttestationPolicyNotSatisfied
    ));
}

#[test]
fn transition_rejects_unlinked_or_deactivated_previous_state() {
    let key = ed25519();
    let doc1 = genesis(&key);
    let doc2 = next_document(&doc1, &key.secret, None, false);
    let doc3 = next_document(&doc2, &key.secret, None, false);

    for (previous, next) in [(&doc1, &doc3), (&doc2, &doc2), (&doc2, &doc1)] {
        let step = validate_did_document_transition(previous, next, no_env());
        assert!(!step.ok);
        assert!(has_code(&step.errors, DidValidationCode::TransitionInvalid));
    }

    // Nothing may follow a terminal deactivation, even if the JSON projection
    // of the terminal document is edited to restore update authority.
    let terminal = next_document(&doc1, &key.secret, None, true);
    let mut revived = terminal.clone();
    revived.verification_method = doc1.verification_method.clone();
    revived.update_policy = doc1.update_policy.clone();
    let after_terminal = next_document(&revived, &key.secret, None, false);
    let step = validate_did_document_transition(&terminal, &after_terminal, no_env());
    assert!(!step.ok);
    assert!(has_code(&step.errors, DidValidationCode::TransitionInvalid));
}

// -----------------------------------------------------------------------------
// M3: P-256 is not an update-authority algorithm
// -----------------------------------------------------------------------------

#[test]
fn p256_update_authority_is_rejected_at_signing() {
    let (_, secret) = generate_keypair(CryptoAlgorithm::P256).unwrap();
    let keys = vec![CoreVerificationMethod {
        id: "#p256".into(),
        vm_type: "Multikey".into(),
        algorithm: Algorithm::P256,
        public_key_multibase: "zUnused".into(),
    }];
    let mut core = genesis_core_for_signing();
    core.controller_keys = keys.clone();

    let result = sign_core(&core, &keys, &["#p256".into()], |_| Some(secret.to_vec()));

    assert_eq!(result.err(), Some(DidCoreError::PolicyViolation));
}

fn genesis_core_for_signing() -> DidCore {
    DidCore {
        id: DID.into(),
        sequence: 1,
        nonce: Some(vec![0; 16]),
        controller: vec![DID.into()],
        controller_keys: vec![],
        authentication: vec![],
        assertion: vec![],
        key_agreement: vec![],
        services: vec![],
        update_policy: UpdatePolicy {
            allowed_verification_methods: vec!["#p256".into()],
            threshold: None,
        },
        prev: None,
    }
}

// -----------------------------------------------------------------------------
// M6 / L8: resource limits and policy reference form
// -----------------------------------------------------------------------------

#[test]
fn oversized_verification_method_list_is_rejected_before_semantic_work() {
    let key = ed25519();
    let mut doc = genesis(&key);
    let template = doc.verification_method[0].clone();
    doc.verification_method = (0..=MAX_VERIFICATION_METHODS)
        .map(|index| {
            let mut method = template.clone();
            method.id = format!("#k{index}");
            method
        })
        .collect();

    let result = validate_did_document(&doc, no_env());

    assert!(!result.ok);
    assert_eq!(result.errors.len(), 1);
    assert!(has_code(
        &result.errors,
        DidValidationCode::ResourceLimitExceeded
    ));
}

#[test]
fn absolute_update_policy_reference_is_rejected() {
    let key = ed25519();
    let mut doc = genesis(&key);
    if let Some(policy) = doc.update_policy.as_mut() {
        policy.allowed_verification_methods = vec![format!("{DID}#k1")];
    }

    let result = validate_did_document(&doc, no_env());

    assert!(!result.ok);
    assert!(has_code(
        &result.errors,
        DidValidationCode::UpdatePolicyInvalid
    ));
}

// -----------------------------------------------------------------------------
// M8: domain verification only dereferences fixed targets for valid bindings
// -----------------------------------------------------------------------------

fn dns_binding(domain: &str, did: &str) -> DomainVerification {
    DomainVerification {
        verification_type: "DnsTxtVerification".into(),
        method: "dns".into(),
        domain: domain.into(),
        dns: Some(DNSBinding {
            record_name: "_did".into(),
            txt_value: did.into(),
        }),
        wellknown: None,
    }
}

fn wellknown_binding(domain: &str, uri: &str, did: &str) -> DomainVerification {
    DomainVerification {
        verification_type: "HttpsWellKnownVerification".into(),
        method: "wellknown".into(),
        domain: domain.into(),
        dns: None,
        wellknown: Some(WellKnownBinding {
            uri: uri.into(),
            content: did.into(),
        }),
    }
}

#[test]
fn dns_verification_queries_the_did_record_label() {
    let queried = std::cell::RefCell::new(Vec::new());
    let resolve = |name: &str| {
        queried.borrow_mut().push(name.to_owned());
        Ok(vec![DID.to_owned()])
    };
    let env = DomainVerificationEnv {
        resolve_txt: Some(&resolve),
        fetch_url: None,
    };
    let view = DidDocumentViewForDV { id: DID };

    assert_eq!(
        validate_domain_entry(&dns_binding("example.com", DID), &view, &env),
        Ok(true)
    );
    assert_eq!(queried.borrow().as_slice(), ["_did.example.com".to_owned()]);
}

#[test]
fn invalid_domains_and_uris_are_never_dereferenced() {
    let calls = Cell::new(0usize);
    let resolve = |_: &str| {
        calls.set(calls.get() + 1);
        Ok(vec![DID.to_owned()])
    };
    let fetch = |_: &str| {
        calls.set(calls.get() + 1);
        Ok(format!(r#"{{"domain":"example.com","did":"{DID}"}}"#))
    };
    let env = DomainVerificationEnv {
        resolve_txt: Some(&resolve),
        fetch_url: Some(&fetch),
    };
    let view = DidDocumentViewForDV { id: DID };

    for domain in [
        "169.254.169.254",
        "localhost",
        "example.com/admin",
        "example.com:8443",
        "user@example.com",
        "Example.com",
        "example.com.",
    ] {
        assert_eq!(
            validate_domain_entry(&dns_binding(domain, DID), &view, &env),
            Err(DomainVerificationError::InvalidDomain)
        );
    }
    assert_eq!(
        validate_domain_entry(
            &wellknown_binding("example.com", "https://169.254.169.254/latest", DID),
            &view,
            &env,
        ),
        Err(DomainVerificationError::InvalidWellKnownUri)
    );
    assert_eq!(
        validate_domain_entry(&dns_binding("example.com", "did:me:other"), &view, &env),
        Err(DomainVerificationError::BindingMismatch)
    );
    assert_eq!(calls.get(), 0);
}

#[test]
fn document_validation_skips_lookups_for_invalid_bindings() {
    let calls = Cell::new(0usize);
    let fetch = |_: &str| {
        calls.set(calls.get() + 1);
        Ok(String::new())
    };
    let env = DomainVerificationEnv {
        resolve_txt: None,
        fetch_url: Some(&fetch),
    };
    let key = ed25519();
    let mut doc = genesis(&key);
    doc.domain_verification = vec![wellknown_binding(
        "example.com",
        "https://attacker.example/steal",
        DID,
    )];

    let result = validate_did_document(&doc, env);

    assert!(!result.ok);
    assert!(has_code(
        &result.errors,
        DidValidationCode::DomainBindingInvalid
    ));
    assert_eq!(calls.get(), 0);
}
