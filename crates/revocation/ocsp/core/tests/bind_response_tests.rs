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
//! Tests for binding host-produced OCSP results to submitted certificates.

use envelopes_x509::parse_cert_der;
use identity_revocation_ocsp_core::{
    bind_response_to_certificates, OcspCertStatus, OcspError, ParsedOcspResponse,
};

fn fixture(name: &str) -> Vec<u8> {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../openssl/tests/fixtures")
        .join(name);
    std::fs::read(path).unwrap()
}

fn honest_response() -> ParsedOcspResponse {
    let leaf = parse_cert_der(&fixture("leaf.der")).unwrap();
    let issuer = parse_cert_der(&fixture("issuer.der")).unwrap();
    ParsedOcspResponse {
        issuer_key: issuer.subject_key_identifier.clone().unwrap(),
        serial: leaf.serial.clone(),
        status: OcspCertStatus::Good,
        this_update: 1_767_656_420,
        next_update: Some(1_768_261_220),
        signature_valid: Some(true),
        responder_authorized: Some(true),
        responder_eku_ocsp_signing: Some(true),
        extensions: None,
    }
}

#[test]
fn honest_host_response_is_accepted() {
    let bound = bind_response_to_certificates(
        honest_response(),
        &fixture("leaf.der"),
        &fixture("issuer.der"),
    )
    .unwrap();

    assert_eq!(bound.status, OcspCertStatus::Good);
}

#[test]
fn serial_with_sign_padding_is_accepted() {
    let mut response = honest_response();
    response.serial.insert(0, 0);

    assert!(
        bind_response_to_certificates(response, &fixture("leaf.der"), &fixture("issuer.der"))
            .is_ok()
    );
}

#[test]
fn response_for_another_serial_is_rejected() {
    let mut response = honest_response();
    response.serial = vec![0x7F, 0x7F];

    assert_eq!(
        bind_response_to_certificates(response, &fixture("leaf.der"), &fixture("issuer.der"))
            .unwrap_err(),
        OcspError::InvalidResponse
    );
}

#[test]
fn response_for_another_issuer_key_is_rejected() {
    let mut response = honest_response();
    response.issuer_key = vec![0xAB; 20];

    assert_eq!(
        bind_response_to_certificates(response, &fixture("leaf.der"), &fixture("issuer.der"))
            .unwrap_err(),
        OcspError::InvalidResponse
    );
}

#[test]
fn issuer_that_did_not_issue_certificate_is_rejected() {
    let mut response = honest_response();
    let root = parse_cert_der(&fixture("root.der")).unwrap();
    response.issuer_key = root.subject_key_identifier.clone().unwrap();

    assert_eq!(
        bind_response_to_certificates(response, &fixture("leaf.der"), &fixture("root.der"))
            .unwrap_err(),
        OcspError::InvalidResponse
    );
}

#[test]
fn inverted_or_zero_validity_window_is_rejected() {
    let mut inverted = honest_response();
    inverted.next_update = Some(inverted.this_update - 1);
    assert_eq!(
        bind_response_to_certificates(inverted, &fixture("leaf.der"), &fixture("issuer.der"))
            .unwrap_err(),
        OcspError::InvalidResponse
    );

    let mut zero = honest_response();
    zero.this_update = 0;
    assert_eq!(
        bind_response_to_certificates(zero, &fixture("leaf.der"), &fixture("issuer.der"))
            .unwrap_err(),
        OcspError::InvalidResponse
    );
}

#[test]
fn malformed_certificate_der_is_rejected() {
    assert_eq!(
        bind_response_to_certificates(honest_response(), &[0x30, 0x00], &fixture("issuer.der"))
            .unwrap_err(),
        OcspError::InvalidResponse
    );
}
