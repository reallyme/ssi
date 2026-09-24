// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Tests for the canonical identity algorithm registry.
//

use reallyme_ssi_core::{lookup_by_algorithm, lookup_by_multicodec_name, Algorithm, KeyRole};

fn assert_registry_entry(
    alg: Algorithm,
    multicodec_name: &'static str,
    public_key_len: usize,
    role: KeyRole,
) {
    assert_eq!(
        lookup_by_algorithm(alg).map(|spec| {
            (
                spec.multicodec_name,
                spec.public_key_len,
                spec.role,
                spec.alg,
            )
        }),
        Some((multicodec_name, public_key_len, role, alg))
    );
    assert_eq!(
        lookup_by_multicodec_name(multicodec_name).map(|spec| {
            (
                spec.multicodec_name,
                spec.public_key_len,
                spec.role,
                spec.alg,
            )
        }),
        Some((multicodec_name, public_key_len, role, alg))
    );
}

#[test]
fn ed25519_spec_is_correct() {
    assert_registry_entry(Algorithm::Ed25519, "ed25519-pub", 32, KeyRole::Signing);
}

#[test]
fn x25519_spec_is_correct() {
    assert_registry_entry(Algorithm::X25519, "x25519-pub", 32, KeyRole::KeyAgreement);
}

#[test]
fn p256_spec_is_correct() {
    assert_registry_entry(Algorithm::P256, "p256-pub", 33, KeyRole::Signing);
}

#[test]
fn secp256k1_spec_is_correct() {
    assert_registry_entry(Algorithm::Secp256k1, "secp256k1-pub", 33, KeyRole::Signing);
}

#[test]
fn mldsa87_spec_is_correct() {
    assert_registry_entry(Algorithm::MlDsa87, "mldsa-87-pub", 2592, KeyRole::Signing);
}

#[test]
fn mlkem768_spec_is_correct() {
    assert_registry_entry(Algorithm::MlKem768, "mlkem-768-pub", 1184, KeyRole::Kem);
}

#[test]
fn mlkem1024_spec_is_correct() {
    assert_registry_entry(Algorithm::MlKem1024, "mlkem-1024-pub", 1568, KeyRole::Kem);
}

#[test]
fn lookup_by_multicodec_name_rejects_unknown_name() {
    assert!(lookup_by_multicodec_name("unknown-pub").is_none());
}
