// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Test coverage for this crate.
#![allow(missing_docs)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::panic)]
#![allow(clippy::expect_used)]

use identity_core_primitives::Algorithm;
use reallyme_did_core::{sign_core, CoreVerificationMethod};
use std::collections::HashMap;

// bring in helper
mod helpers;
use helpers::test_core;

#[test]
fn multiple_allowed_keys_produce_multiple_attestations() {
    let mut core = test_core(1, None);

    core.update_policy.allowed_verification_methods = vec!["#k1".into(), "#k2".into()];
    core.update_policy.threshold = None;

    let keys = vec![
        CoreVerificationMethod {
            id: "#k1".into(),
            vm_type: "Multikey".into(),
            algorithm: Algorithm::Ed25519,
            public_key_multibase: "z1".into(),
        },
        CoreVerificationMethod {
            id: "#k2".into(),
            vm_type: "Multikey".into(),
            algorithm: Algorithm::Ed25519,
            public_key_multibase: "z2".into(),
        },
    ];

    let mut secrets: HashMap<String, Vec<u8>> = HashMap::new();
    secrets.insert("#k1".into(), vec![1u8; 32]);
    secrets.insert("#k2".into(), vec![2u8; 32]);

    let attestations = sign_core(
        &core,
        &keys,
        &core.update_policy.allowed_verification_methods,
        |id| secrets.get(id).cloned(),
    )
    .unwrap();

    assert_eq!(attestations.len(), 2);
}

#[test]
fn threshold_requires_enough_allowed_signatures() {
    let mut core = test_core(1, None);

    core.update_policy.allowed_verification_methods = vec!["#k1".into(), "#k2".into()];
    core.update_policy.threshold = Some(2);

    let keys = vec![
        CoreVerificationMethod {
            id: "#k1".into(),
            vm_type: "Multikey".into(),
            algorithm: Algorithm::Ed25519,
            public_key_multibase: "z1".into(),
        },
        CoreVerificationMethod {
            id: "#k2".into(),
            vm_type: "Multikey".into(),
            algorithm: Algorithm::Ed25519,
            public_key_multibase: "z2".into(),
        },
    ];

    let mut secrets: HashMap<String, Vec<u8>> = HashMap::new();
    secrets.insert("#k1".into(), vec![1u8; 32]);

    let res = sign_core(
        &core,
        &keys,
        &core.update_policy.allowed_verification_methods,
        |id| secrets.get(id).cloned(),
    );

    assert!(
        res.is_err(),
        "signing must fail when attestations cannot satisfy the threshold"
    );
}

#[test]
fn threshold_one_does_not_require_every_allowed_private_key() {
    let mut core = test_core(1, None);

    core.update_policy.allowed_verification_methods = vec!["#k1".into(), "#k2".into()];
    core.update_policy.threshold = Some(1);

    let keys = vec![
        CoreVerificationMethod {
            id: "#k1".into(),
            vm_type: "Multikey".into(),
            algorithm: Algorithm::Ed25519,
            public_key_multibase: "z1".into(),
        },
        CoreVerificationMethod {
            id: "#k2".into(),
            vm_type: "Multikey".into(),
            algorithm: Algorithm::Ed25519,
            public_key_multibase: "z2".into(),
        },
    ];

    let mut secrets: HashMap<String, Vec<u8>> = HashMap::new();
    secrets.insert("#k1".into(), vec![1u8; 32]);

    let attestations = sign_core(
        &core,
        &keys,
        &core.update_policy.allowed_verification_methods,
        |id| secrets.get(id).cloned(),
    )
    .unwrap();

    assert_eq!(attestations.len(), 1);
    assert_eq!(attestations[0].verification_method, "#k1");
}

#[test]
fn signing_order_is_deterministic() {
    let mut core = test_core(1, None);

    core.update_policy.allowed_verification_methods = vec!["#a".into(), "#b".into()];
    core.update_policy.threshold = None;

    let keys = vec![
        CoreVerificationMethod {
            id: "#b".into(),
            vm_type: "Multikey".into(),
            algorithm: Algorithm::Ed25519,
            public_key_multibase: "z".into(),
        },
        CoreVerificationMethod {
            id: "#a".into(),
            vm_type: "Multikey".into(),
            algorithm: Algorithm::Ed25519,
            public_key_multibase: "z".into(),
        },
    ];

    let mut secrets: HashMap<String, Vec<u8>> = HashMap::new();
    secrets.insert("#a".into(), vec![1u8; 32]);
    secrets.insert("#b".into(), vec![2u8; 32]);

    let a1 = sign_core(
        &core,
        &keys,
        &core.update_policy.allowed_verification_methods,
        |id| secrets.get(id).cloned(),
    )
    .unwrap();

    let a2 = sign_core(
        &core,
        &keys,
        &core.update_policy.allowed_verification_methods,
        |id| secrets.get(id).cloned(),
    )
    .unwrap();

    assert_eq!(a1, a2);
}
