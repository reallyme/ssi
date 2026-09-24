// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Test coverage for this crate.
#![allow(missing_docs)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::panic)]
#![allow(clippy::expect_used)]

use identity_core_primitives::Algorithm;
use reallyme_did_core::keys::{
    generate_keypair_for_algorithm, public_key_to_multikey_for_algorithm,
};

/// Helper to assert basic key invariants
fn assert_keypair(pubk: &[u8], seck: &[u8], min_pub: usize, min_sec: usize) {
    assert!(!pubk.is_empty(), "public key must not be empty");
    assert!(!seck.is_empty(), "secret key must not be empty");
    assert!(
        pubk.len() >= min_pub,
        "public key length too small: {}",
        pubk.len()
    );
    assert!(
        seck.len() >= min_sec,
        "secret key length too small: {}",
        seck.len()
    );
}

#[test]
fn ed25519_keypair_and_multikey() {
    let (pubk, seck) = generate_keypair_for_algorithm(Algorithm::Ed25519).unwrap();

    assert_keypair(&pubk, &seck, 32, 32);

    let mk = public_key_to_multikey_for_algorithm(Algorithm::Ed25519, &pubk).unwrap();

    assert!(mk.starts_with('z'), "multikey must be multibase");
    assert!(mk.contains("z"), "multikey must be base58btc");
}

#[test]
fn p256_keypair_and_multikey() {
    let (pubk, seck) = generate_keypair_for_algorithm(Algorithm::P256).unwrap();

    // compressed SEC1 pubkey
    assert_keypair(&pubk, &seck, 33, 32);

    let mk = public_key_to_multikey_for_algorithm(Algorithm::P256, &pubk).unwrap();

    assert!(mk.starts_with('z'));
}

#[test]
fn secp256k1_keypair_and_multikey() {
    let (pubk, seck) = generate_keypair_for_algorithm(Algorithm::Secp256k1).unwrap();

    assert_keypair(&pubk, &seck, 33, 32);

    let mk = public_key_to_multikey_for_algorithm(Algorithm::Secp256k1, &pubk).unwrap();

    assert!(mk.starts_with('z'));
}

#[test]
fn mldsa87_keypair_and_multikey() {
    let (pubk, seck) = generate_keypair_for_algorithm(Algorithm::MlDsa87).unwrap();

    assert_keypair(&pubk, &seck, 2592, 32);

    let mk = public_key_to_multikey_for_algorithm(Algorithm::MlDsa87, &pubk).unwrap();

    assert!(mk.starts_with('z'));
}

#[test]
fn x25519_keypair_and_multikey() {
    let (pubk, seck) = generate_keypair_for_algorithm(Algorithm::X25519).unwrap();

    assert_keypair(&pubk, &seck, 32, 32);

    let mk = public_key_to_multikey_for_algorithm(Algorithm::X25519, &pubk).unwrap();

    assert!(mk.starts_with('z'));
}

#[test]
fn mlkem1024_keypair_and_multikey() {
    let (pubk, seck) = generate_keypair_for_algorithm(Algorithm::MlKem1024).unwrap();

    assert_keypair(&pubk, &seck, 1568, 64);

    let mk = public_key_to_multikey_for_algorithm(Algorithm::MlKem1024, &pubk).unwrap();

    assert!(mk.starts_with('z'));
}

#[test]
fn different_keypairs_are_not_equal() {
    let (p1, s1) = generate_keypair_for_algorithm(Algorithm::Ed25519).unwrap();
    let (p2, s2) = generate_keypair_for_algorithm(Algorithm::Ed25519).unwrap();

    assert_ne!(p1, p2, "public keys must differ");
    assert_ne!(s1, s2, "secret keys must differ");
}

#[test]
fn multikey_encoding_rejects_wrong_public_key_length() {
    let bad_pub = vec![0u8; 10];

    let err = public_key_to_multikey_for_algorithm(Algorithm::Ed25519, &bad_pub);

    assert!(err.is_err(), "invalid public key must be rejected");
}
