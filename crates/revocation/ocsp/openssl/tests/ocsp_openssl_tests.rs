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
//! Tests for OpenSSL-backed OCSP parsing.

use identity_revocation_ocsp_core::OcspCertStatus;
use identity_revocation_ocsp_openssl::parse_ocsp_response_der;

use openssl::x509::X509;

fn read(path: &str) -> Vec<u8> {
    std::fs::read(path).unwrap()
}

#[test]
fn parses_and_verifies_ocsp_response_fixture() {
    let issuer_der = read("tests/fixtures/issuer.der");
    let leaf_der = read("tests/fixtures/leaf.der");
    let ocsp_resp_der = read("tests/fixtures/ocsp.resp.der");
    let root_der = read("tests/fixtures/root.der");

    let issuer = X509::from_der(&issuer_der).unwrap();
    let leaf = X509::from_der(&leaf_der).unwrap();
    let root = X509::from_der(&root_der).unwrap();

    let now = time::OffsetDateTime::now_utc().unix_timestamp() as u64;

    let parsed = parse_ocsp_response_der(&ocsp_resp_der, &leaf, &issuer, &[root], now).unwrap();

    assert_eq!(
        parsed.serial,
        leaf.serial_number().to_bn().unwrap().to_vec()
    );

    assert!(!parsed.issuer_key.is_empty());

    assert!(matches!(
        parsed.status,
        OcspCertStatus::Good | OcspCertStatus::Revoked | OcspCertStatus::Unknown
    ));
}
