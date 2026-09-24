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
//! Tests for OpenSSL-backed CRL parsing.

use identity_revocation_crl_core::CrlChecker;
use identity_revocation_crl_openssl::parse_crl_der_with_env_issuer;

use identity_revocation_core::{StatusCheckError, StatusChecker};

use envelopes_x509::parse_cert_der;
use openssl::x509::X509;

fn read(path: &str) -> Vec<u8> {
    std::fs::read(path).unwrap()
}

#[test]
fn crl_checker_detects_revocation() {
    let root_der = read("tests/fixtures/root.der");
    let leaf_der = read("tests/fixtures/leaf.der");
    let crl_der = read("tests/fixtures/revoked.crl.der");

    let root = X509::from_der(&root_der).unwrap();
    let leaf_env = parse_cert_der(&leaf_der).unwrap();

    // OpenSSL parse
    let parsed_openssl = parse_crl_der_with_env_issuer(&crl_der, root).unwrap();

    // OK Convert into portable core model
    let parsed_crl = parsed_openssl.into();

    let checker = CrlChecker::new(vec![parsed_crl]);

    let now = time::OffsetDateTime::now_utc().unix_timestamp() as u64;
    let err = checker.check(&leaf_env, now).unwrap_err();

    assert!(matches!(err, StatusCheckError::Revoked));
}

#[test]
fn crl_checker_allows_non_revoked() {
    let root_der = read("tests/fixtures/root.der");
    let leaf_der = read("tests/fixtures/leaf.der");
    let crl_der = read("tests/fixtures/clean.crl.der");

    let root = X509::from_der(&root_der).unwrap();
    let leaf_env = parse_cert_der(&leaf_der).unwrap();

    let parsed_openssl = parse_crl_der_with_env_issuer(&crl_der, root).unwrap();

    let parsed_crl = parsed_openssl.into();

    let checker = CrlChecker::new(vec![parsed_crl]);

    let now = time::OffsetDateTime::now_utc().unix_timestamp() as u64;
    checker.check(&leaf_env, now).unwrap();
}
