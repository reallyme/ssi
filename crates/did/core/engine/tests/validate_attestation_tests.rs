// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Test coverage for this crate.
#![allow(missing_docs)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::panic)]
#![allow(clippy::expect_used)]

use identity_core_primitives::algorithm_map::{alg_to_did_alg_str, alg_to_vc_alg_str};
use identity_core_primitives::Algorithm;
use reallyme_did_core::signing::sign_core;
use reallyme_did_core::validate::attestation::validate_attestations;
use reallyme_did_core::{Canonical, CoreVerificationMethod};
use reallyme_did_types::{Attestation, VerificationMethod};

use reallyme_crypto::core::Algorithm as CryptoAlgorithm;
use reallyme_crypto::dispatch::{generate_keypair, public_key_to_multikey};

use reallyme_codec::base64url::bytes_to_base64url;

mod helpers;
use helpers::test_core;

#[test]
fn valid_mldsa87_attestation_passes() {
    // --------------------------------------------------
    // 1. Build core via helper
    // --------------------------------------------------
    let mut core = test_core(1, None);

    core.controller_keys = vec![CoreVerificationMethod {
        id: "#mldsa87-root".into(),
        vm_type: "Multikey".into(),
        algorithm: Algorithm::MlDsa87,
        public_key_multibase: String::new(),
    }];

    core.update_policy.allowed_verification_methods = vec!["#mldsa87-root".into()];
    core.update_policy.threshold = None;

    // --------------------------------------------------
    // 2. Generate ML-DSA-87 keypair
    // --------------------------------------------------
    let (public, secret) = generate_keypair(CryptoAlgorithm::MlDsa87).unwrap();

    let multikey = public_key_to_multikey(CryptoAlgorithm::MlDsa87, &public).unwrap();

    core.controller_keys[0].public_key_multibase = multikey.clone();

    // --------------------------------------------------
    // 3. Sign core
    // --------------------------------------------------
    let core_attestations = sign_core(
        &core,
        &core.controller_keys,
        &["#mldsa87-root".into()],
        |_| Some(secret.to_vec()),
    )
    .unwrap();

    // --------------------------------------------------
    // 4. Convert Core → JSON types
    // --------------------------------------------------
    let vms: Vec<VerificationMethod> = core
        .controller_keys
        .iter()
        .map(|vm| VerificationMethod {
            id: vm.id.clone(),
            vm_type: vm.vm_type.clone(),
            controller: core.id.clone(),
            algorithm: Some(alg_to_did_alg_str(vm.algorithm).to_string()),
            public_key_multibase: vm.public_key_multibase.clone(),
        })
        .collect();

    let atts: Vec<Attestation> = core_attestations
        .iter()
        .map(|a| Attestation {
            alg: a.algorithm.clone(),
            vm: a.verification_method.clone(),
            sig: a.signature.clone(),
        })
        .collect();

    let core_cbor_b64 = bytes_to_base64url(&core.canonical_cbor().unwrap());

    // --------------------------------------------------
    // 5. Validate
    // --------------------------------------------------
    let res = validate_attestations(&vms, &atts, &core_cbor_b64);

    assert!(res.ok, "ML-DSA-87 attestation should validate");
    assert!(res.errors.is_empty());
}

#[test]
fn valid_ed25519_attestation_passes() {
    // --------------------------------------------------
    // 1. Build core via helper
    // --------------------------------------------------
    let mut core = test_core(1, None);

    core.controller_keys = vec![CoreVerificationMethod {
        id: "#ed25519".into(),
        vm_type: "Multikey".into(),
        algorithm: Algorithm::Ed25519,
        public_key_multibase: String::new(),
    }];

    core.update_policy.allowed_verification_methods = vec!["#ed25519".into()];
    core.update_policy.threshold = None;

    // --------------------------------------------------
    // 2. Generate Ed25519 keypair
    // --------------------------------------------------
    let (public, secret) = generate_keypair(CryptoAlgorithm::Ed25519).unwrap();

    let multikey = public_key_to_multikey(CryptoAlgorithm::Ed25519, &public).unwrap();

    core.controller_keys[0].public_key_multibase = multikey.clone();

    // --------------------------------------------------
    // 3. Sign core
    // --------------------------------------------------
    let core_attestations = sign_core(&core, &core.controller_keys, &["#ed25519".into()], |_| {
        Some(secret.to_vec())
    })
    .unwrap();

    // --------------------------------------------------
    // 4. Convert Core → JSON types
    // --------------------------------------------------
    let vms: Vec<VerificationMethod> = core
        .controller_keys
        .iter()
        .map(|vm| VerificationMethod {
            id: vm.id.clone(),
            vm_type: vm.vm_type.clone(),
            controller: core.id.clone(),
            algorithm: Some(alg_to_did_alg_str(vm.algorithm).to_string()),
            public_key_multibase: vm.public_key_multibase.clone(),
        })
        .collect();

    let atts: Vec<Attestation> = core_attestations
        .iter()
        .map(|a| Attestation {
            alg: a.algorithm.clone(),
            vm: a.verification_method.clone(),
            sig: a.signature.clone(),
        })
        .collect();

    let core_cbor_b64 = bytes_to_base64url(&core.canonical_cbor().unwrap());

    // --------------------------------------------------
    // 5. Validate
    // --------------------------------------------------
    let res = validate_attestations(&vms, &atts, &core_cbor_b64);

    assert!(res.ok, "Ed25519 attestation should validate");
    assert!(res.errors.is_empty());
}

#[test]
fn ed25519_attestation_rejects_jose_algorithm_alias() {
    let mut core = test_core(1, None);

    core.controller_keys = vec![CoreVerificationMethod {
        id: "#ed25519".into(),
        vm_type: "Multikey".into(),
        algorithm: Algorithm::Ed25519,
        public_key_multibase: String::new(),
    }];

    let (public, secret) = generate_keypair(CryptoAlgorithm::Ed25519).unwrap();
    core.controller_keys[0].public_key_multibase =
        public_key_to_multikey(CryptoAlgorithm::Ed25519, &public).unwrap();

    let core_attestations = sign_core(&core, &core.controller_keys, &["#ed25519".into()], |_| {
        Some(secret.to_vec())
    })
    .unwrap();

    let vms = vec![VerificationMethod {
        id: "#ed25519".into(),
        vm_type: "Multikey".into(),
        controller: core.id.clone(),
        algorithm: Some("Ed25519".into()),
        public_key_multibase: core.controller_keys[0].public_key_multibase.clone(),
    }];

    let atts: Vec<Attestation> = core_attestations
        .iter()
        .map(|a| Attestation {
            alg: alg_to_vc_alg_str(Algorithm::Ed25519).to_string(),
            vm: a.verification_method.clone(),
            sig: a.signature.clone(),
        })
        .collect();

    let core_cbor_b64 = bytes_to_base64url(&core.canonical_cbor().unwrap());
    let res = validate_attestations(&vms, &atts, &core_cbor_b64);

    assert!(
        !res.ok,
        "DID attestations must use canonical DID algorithm names"
    );
}
