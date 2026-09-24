// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::print_stderr
)]
//! Tests for portable CRL status checking.

use identity_revocation_core::{StatusCheckError, StatusChecker};
use identity_revocation_crl_core::{CrlChecker, ParsedCrl};

use envelopes_x509::parse_cert_der;

fn read(path: &str) -> Vec<u8> {
    std::fs::read(path).unwrap()
}

#[test]
fn crl_checker_detects_revocation() {
    let leaf_der = read("tests/fixtures/leaf.der");

    let leaf = parse_cert_der(&leaf_der).unwrap();

    let issuer_key = leaf.authority_key_identifier.as_ref().unwrap().clone();

    let revoked_serial = leaf.serial.clone();

    let crl = ParsedCrl {
        issuer_key,
        revoked_serials: vec![revoked_serial],
        this_update_unix: Some(1_700_000_000),
        next_update_unix: Some(1_800_000_000),
    };

    let checker = CrlChecker::new(vec![crl]);

    let err = checker.check(&leaf, 1_750_000_000).unwrap_err();

    assert!(matches!(err, StatusCheckError::Revoked));
}

#[test]
fn crl_checker_allows_non_revoked() {
    let leaf_der = read("tests/fixtures/leaf.der");

    let leaf = parse_cert_der(&leaf_der).unwrap();

    let issuer_key = leaf.authority_key_identifier.as_ref().unwrap().clone();

    let crl = ParsedCrl {
        issuer_key,
        revoked_serials: vec![b"\xAA\xBB\xCC".to_vec()],
        this_update_unix: Some(1_700_000_000),
        next_update_unix: Some(1_800_000_000),
    };

    let checker = CrlChecker::new(vec![crl]);

    checker.check(&leaf, 1_750_000_000).unwrap();
}
