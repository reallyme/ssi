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

use identity_revocation_ocsp_core::{OcspCertStatus, OcspError};
use identity_revocation_ocsp_openssl::parse_ocsp_response_der;

use openssl::x509::X509;

/// 2026-01-06T00:00:00Z, inside the fixture certificate and response validity.
const FIXTURE_NOW: u64 = 1_767_657_600;

fn read(path: &str) -> Vec<u8> {
    std::fs::read(path).unwrap()
}

fn fixture_certs() -> (Vec<u8>, X509, X509, X509) {
    (
        read("tests/fixtures/ocsp.resp.der"),
        X509::from_der(&read("tests/fixtures/leaf.der")).unwrap(),
        X509::from_der(&read("tests/fixtures/issuer.der")).unwrap(),
        X509::from_der(&read("tests/fixtures/root.der")).unwrap(),
    )
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

    let parsed =
        parse_ocsp_response_der(&ocsp_resp_der, &leaf, &issuer, &[root], FIXTURE_NOW).unwrap();

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

#[test]
fn fixture_times_are_populated() {
    let (ocsp, leaf, issuer, root) = fixture_certs();

    let parsed = parse_ocsp_response_der(&ocsp, &leaf, &issuer, &[root], FIXTURE_NOW).unwrap();

    assert!(matches!(parsed.status, OcspCertStatus::Good));
    assert_eq!(parsed.next_update, Some(parsed.this_update + 7 * 86_400));
}

#[test]
fn responder_chain_is_verified_at_supplied_time_not_wall_clock() {
    let (ocsp, leaf, issuer, root) = fixture_certs();

    // After every fixture certificate has expired (2039).
    assert_eq!(
        parse_ocsp_response_der(
            &ocsp,
            &leaf,
            &issuer,
            std::slice::from_ref(&root),
            2_200_000_000
        )
        .unwrap_err(),
        OcspError::UntrustedResponder
    );
    // Before the fixture certificates became valid (2023).
    assert_eq!(
        parse_ocsp_response_der(&ocsp, &leaf, &issuer, &[root], 1_700_000_000).unwrap_err(),
        OcspError::UntrustedResponder
    );
}

#[test]
fn verification_time_outside_platform_range_is_rejected() {
    let (ocsp, leaf, issuer, root) = fixture_certs();

    assert_eq!(
        parse_ocsp_response_der(&ocsp, &leaf, &issuer, &[root], u64::MAX).unwrap_err(),
        OcspError::InvalidResponse
    );
}

#[test]
fn tampered_response_is_rejected() {
    let (mut ocsp, leaf, issuer, root) = fixture_certs();
    let last = ocsp.len() - 1;
    ocsp[last] ^= 0x01;

    assert!(parse_ocsp_response_der(&ocsp, &leaf, &issuer, &[root], FIXTURE_NOW).is_err());
}

#[test]
fn extra_certificates_cannot_replace_the_configured_issuer() {
    let (ocsp, leaf, issuer, root) = fixture_certs();

    assert!(parse_ocsp_response_der(
        &ocsp,
        &leaf,
        &root,
        std::slice::from_ref(&issuer),
        FIXTURE_NOW,
    )
    .is_err());
}
