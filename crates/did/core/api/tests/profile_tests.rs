// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Test coverage for this crate.
#![allow(missing_docs)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::panic)]
#![allow(clippy::expect_used)]

use reallyme_did_api::profile::{build_profile, DidProfile};

/// Helper for String-based ID vectors
fn ids(v: &[String]) -> Vec<&str> {
    v.iter().map(|s| s.as_str()).collect()
}

#[test]
fn core_identity_profile_is_exact() {
    let did = "did:me:test";
    let opts = build_profile(DidProfile::CoreIdentity, did);

    assert_eq!(opts.id, did);
    assert_eq!(opts.sequence, 1);
    assert!(opts.prev.is_none());

    // --- controller keys ---
    let vm_ids: Vec<&str> = opts.controller_keys.iter().map(|v| v.id.as_str()).collect();
    assert_eq!(
        vm_ids,
        vec![
            "#mldsa87-root",
            "#mldsa87-auth",
            "#ed25519",
            "#p256",
            "#x25519",
            "#mlkem768",
            "#mlkem1024",
        ]
    );

    // --- relationships ---
    assert_eq!(
        ids(&opts.authentication),
        vec!["#ed25519", "#mldsa87-auth", "#p256"]
    );
    assert_eq!(
        ids(&opts.assertion),
        vec!["#ed25519", "#p256", "#mldsa87-auth"]
    );
    assert_eq!(ids(&opts.invocation), vec!["#mldsa87-root", "#ed25519"]);
    assert_eq!(
        ids(&opts.key_agreement),
        vec!["#x25519", "#mlkem768", "#mlkem1024"]
    );

    // --- update policy ---
    assert_eq!(
        ids(&opts.allowed_verification_methods),
        vec!["#mldsa87-root", "#ed25519"]
    );
    assert_eq!(opts.threshold, Some(2));
}

#[test]
fn messaging_profile_is_minimal_and_safe() {
    let did = "did:me:msg";
    let opts = build_profile(DidProfile::Messaging, did);

    let vm_ids: Vec<&str> = opts.controller_keys.iter().map(|v| v.id.as_str()).collect();
    assert_eq!(
        vm_ids,
        vec!["#ed25519", "#x25519", "#mlkem768", "#mlkem1024"]
    );

    assert_eq!(ids(&opts.authentication), vec!["#ed25519"]);
    assert!(opts.assertion.is_empty());
    assert_eq!(ids(&opts.invocation), vec!["#ed25519"]);
    assert_eq!(
        ids(&opts.key_agreement),
        vec!["#x25519", "#mlkem768", "#mlkem1024"]
    );

    assert_eq!(ids(&opts.allowed_verification_methods), vec!["#ed25519"]);
    assert_eq!(opts.threshold, None);
}

#[test]
fn payment_profile_is_secp256k1_only() {
    let did = "did:me:pay";
    let opts = build_profile(DidProfile::Payment, did);

    assert_eq!(opts.controller_keys.len(), 1);
    let vm = &opts.controller_keys[0];

    assert_eq!(vm.id, "#k1");
    assert_eq!(vm.algorithm.as_deref(), Some("secp256k1"));

    assert_eq!(ids(&opts.allowed_verification_methods), vec!["#k1"]);
    assert_eq!(opts.threshold, None);

    assert_eq!(ids(&opts.authentication), vec!["#k1"]);
    assert_eq!(ids(&opts.invocation), vec!["#k1"]);
    assert!(opts.key_agreement.is_empty());
}
