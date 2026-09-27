// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::print_stderr
)]
//! Tests for OpenSSL-backed OCSP parsing.

use identity_revocation_ocsp_core::{OcspCertStatus, OcspError};
use identity_revocation_ocsp_openssl::{
    parse_ocsp_response_der, parse_ocsp_response_der_with_nonce,
};

/// 2026-01-06T00:00:00Z, inside the fixture certificate and response validity.
const FIXTURE_NOW: u64 = 1_767_657_600;

fn read(path: &str) -> Vec<u8> {
    std::fs::read(path).unwrap()
}

fn fixture_certs() -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
    (
        read("tests/fixtures/ocsp.resp.der"),
        read("tests/fixtures/leaf.der"),
        read("tests/fixtures/issuer.der"),
        read("tests/fixtures/root.der"),
    )
}

#[test]
fn parses_and_verifies_ocsp_response_fixture() {
    let issuer_der = read("tests/fixtures/issuer.der");
    let leaf_der = read("tests/fixtures/leaf.der");
    let ocsp_resp_der = read("tests/fixtures/ocsp.resp.der");
    let root_der = read("tests/fixtures/root.der");

    let parsed = parse_ocsp_response_der(
        &ocsp_resp_der,
        &leaf_der,
        &issuer_der,
        &[root_der],
        FIXTURE_NOW,
    )
    .unwrap();

    assert_eq!(
        parsed.serial(),
        envelopes_x509::parse_cert_der(&leaf_der).unwrap().serial
    );

    assert!(!parsed.issuer_key().is_empty());

    assert!(matches!(
        parsed.status(),
        OcspCertStatus::Good | OcspCertStatus::Revoked | OcspCertStatus::Unknown
    ));
}

#[test]
fn fixture_times_are_populated() {
    let (ocsp, leaf, issuer, root) = fixture_certs();

    let parsed = parse_ocsp_response_der(&ocsp, &leaf, &issuer, &[root], FIXTURE_NOW).unwrap();

    assert!(matches!(parsed.status(), OcspCertStatus::Good));
    assert_eq!(
        parsed.next_update(),
        Some(parsed.this_update() + 7 * 86_400)
    );
}

#[test]
fn signed_response_nonce_is_extracted_and_bound() {
    let (ocsp, leaf, issuer, root) = fixture_certs();
    let nonce = [
        0x74, 0xcf, 0xf4, 0x07, 0x20, 0xd3, 0xc5, 0x73, 0x78, 0xf5, 0x0f, 0x6a, 0xf8, 0xba, 0xb8,
        0x57,
    ];

    let parsed = parse_ocsp_response_der_with_nonce(
        &ocsp,
        &leaf,
        &issuer,
        std::slice::from_ref(&root),
        FIXTURE_NOW,
        Some(&nonce),
    )
    .unwrap();
    assert_eq!(parsed.response_nonce(), Some(nonce.as_slice()));

    let mut wrong_nonce = nonce;
    wrong_nonce[0] ^= 1;
    assert_eq!(
        parse_ocsp_response_der_with_nonce(
            &ocsp,
            &leaf,
            &issuer,
            std::slice::from_ref(&root),
            FIXTURE_NOW,
            Some(&wrong_nonce),
        )
        .unwrap_err(),
        OcspError::InvalidResponse
    );
}

#[test]
fn expected_nonce_rejects_a_signed_response_without_a_nonce() {
    let response = read("tests/fixtures/sha256-response.der");
    let leaf = read("tests/fixtures/sha256-leaf.der");
    let issuer = read("tests/fixtures/sha256-issuer.der");

    assert_eq!(
        parse_ocsp_response_der_with_nonce(
            &response,
            &leaf,
            &issuer,
            &[],
            1_790_467_200,
            Some(&[7; 16]),
        )
        .unwrap_err(),
        OcspError::InvalidResponse
    );
}

#[test]
fn verifies_end_to_end_sha256_cert_id() {
    let response = read("tests/fixtures/sha256-response.der");
    let leaf = read("tests/fixtures/sha256-leaf.der");
    let issuer = read("tests/fixtures/sha256-issuer.der");

    let parsed = parse_ocsp_response_der(&response, &leaf, &issuer, &[], 1_790_467_200).unwrap();
    assert_eq!(parsed.status(), OcspCertStatus::Good);
}

#[test]
fn rejects_signed_response_with_duplicate_cert_id_entries() {
    let response = read("tests/fixtures/sha256-duplicate-response.der");
    let leaf = read("tests/fixtures/sha256-leaf.der");
    let issuer = read("tests/fixtures/sha256-issuer.der");

    assert_eq!(
        parse_ocsp_response_der(&response, &leaf, &issuer, &[], 1_790_467_200).unwrap_err(),
        OcspError::InvalidResponse
    );
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
        OcspError::InvalidResponse
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

#[test]
fn leaf_authority_key_identifier_must_bind_the_configured_issuer() {
    let (ocsp, mut leaf, issuer, root) = fixture_certs();
    let parsed_leaf = envelopes_x509::parse_cert_der(&leaf).unwrap();
    let authority_key_identifier = parsed_leaf
        .authority_key_identifier
        .as_deref()
        .expect("fixture leaf has an authority key identifier");
    let offset = leaf
        .windows(authority_key_identifier.len())
        .position(|window| window == authority_key_identifier)
        .expect("fixture DER contains its authority key identifier");
    leaf[offset] ^= 1;

    assert_eq!(
        parse_ocsp_response_der(&ocsp, &leaf, &issuer, &[root], FIXTURE_NOW).unwrap_err(),
        OcspError::InvalidResponse
    );
}
