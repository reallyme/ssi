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
use reallyme_did_core::{build_profile, DidProfile};

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
