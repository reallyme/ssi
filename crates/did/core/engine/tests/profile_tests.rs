// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Test coverage for this crate.
#![allow(missing_docs)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::panic)]
#![allow(clippy::expect_used)]
#![allow(clippy::indexing_slicing)]

use identity_core_primitives::algorithm_map::alg_to_did_alg_str;
use identity_core_primitives::Algorithm;
use reallyme_did_core::validate::DomainVerificationEnv;
use reallyme_did_core::{
    build_profile, create_engine, generate_did_me, public_key_to_multikey_for_algorithm,
    validate_did_document, CoreVerificationMethod, DidProfile, UpdatePolicy,
};

fn authority_algorithm<'a>(
    opts: &'a reallyme_did_core::CreateOptions,
    method_id: &str,
) -> Option<&'a str> {
    opts.controller_keys
        .iter()
        .find(|method| method.id == method_id)
        .and_then(|method| method.algorithm.as_deref())
}

#[test]
fn core_identity_profile_is_correct() {
    let did = "did:me:test";
    let opts = build_profile(DidProfile::CoreIdentity, did);

    assert_eq!(opts.controller, vec![did]);
    assert_eq!(opts.sequence, 1);
    assert!(opts.prev.is_none());

    assert_eq!(
        opts.allowed_verification_methods,
        vec!["#mldsa87-root", "#ed25519"]
    );
    assert_eq!(opts.threshold, Some(2));
    assert_eq!(
        authority_algorithm(&opts, "#mldsa87-root"),
        Some(alg_to_did_alg_str(Algorithm::MlDsa87))
    );
    assert_eq!(
        authority_algorithm(&opts, "#ed25519"),
        Some(alg_to_did_alg_str(Algorithm::Ed25519))
    );
}

#[test]
fn public_profile_uses_post_quantum_update_authority() {
    let opts = build_profile(DidProfile::PublicProfile, "did:me:test");

    assert_eq!(opts.allowed_verification_methods, vec!["#mldsa87-root"]);
    assert_eq!(opts.threshold, None);
    assert_eq!(
        authority_algorithm(&opts, "#mldsa87-root"),
        Some(alg_to_did_alg_str(Algorithm::MlDsa87))
    );
}

#[test]
fn messaging_profile_uses_ed25519_update_authority() {
    let opts = build_profile(DidProfile::Messaging, "did:me:test");

    assert_eq!(opts.allowed_verification_methods, vec!["#ed25519"]);
    assert_eq!(opts.threshold, None);
    assert_eq!(
        authority_algorithm(&opts, "#ed25519"),
        Some(alg_to_did_alg_str(Algorithm::Ed25519))
    );
}

#[test]
fn payment_profile_is_minimal() {
    let did = "did:me:test";
    let opts = build_profile(DidProfile::Payment, did);

    assert_eq!(opts.controller_keys.len(), 1);
    assert_eq!(
        opts.controller_keys[0].algorithm.as_deref(),
        Some("secp256k1")
    );

    assert!(opts.key_agreement.is_empty());
    assert_eq!(opts.threshold, None);
}

#[test]
fn payment_profile_genesis_validates_with_secp256k1_authority() {
    let (public_key, private_key) =
        reallyme_crypto::dispatch::generate_keypair(reallyme_crypto::core::Algorithm::Secp256k1)
            .expect("generate secp256k1 key");
    let mut options = build_profile(DidProfile::Payment, "did:me:profile-placeholder");
    options.controller_keys[0].public_key_multibase =
        public_key_to_multikey_for_algorithm(Algorithm::Secp256k1, public_key.as_slice())
            .expect("encode secp256k1 multikey");
    let nonce = [0_u8; 16];
    let did = generate_did_me(
        &nonce,
        &UpdatePolicy {
            allowed_verification_methods: options.allowed_verification_methods.clone(),
            threshold: options.threshold,
        },
        &[CoreVerificationMethod {
            id: options.controller_keys[0].id.clone(),
            vm_type: options.controller_keys[0].vm_type.clone(),
            algorithm: Algorithm::Secp256k1,
            public_key_multibase: options.controller_keys[0].public_key_multibase.clone(),
        }],
    )
    .expect("derive Payment-profile DID");
    options.id = did.clone();
    options.controller = vec![did.clone()];
    options.controller_keys[0].controller = did;
    options.nonce = Some(nonce.to_vec());

    let created = create_engine(&options, |id| (id == "#k1").then(|| private_key.to_vec()))
        .expect("create Payment-profile genesis");
    let validation = validate_did_document(
        &created.document,
        DomainVerificationEnv {
            resolve_txt: None,
            fetch_url: None,
        },
    );

    assert!(validation.ok, "{:?}", validation.errors);
}
