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
use identity_revocation_ocsp_core::{OcspCertStatus, OcspError, OcspExtension};

use crate::bind_response::bind_response_to_certificates_with_nonce;
use crate::model::UnverifiedOcspResponse;

fn bind_response_to_certificates(
    response: UnverifiedOcspResponse,
    cert_der: &[u8],
    issuer_der: &[u8],
) -> Result<crate::VerifiedOcspResponse, OcspError> {
    bind_response_to_certificates_with_nonce(response, cert_der, issuer_der, None)
}

fn fixture(name: &str) -> Vec<u8> {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name);
    std::fs::read(path).unwrap()
}

fn honest_response() -> UnverifiedOcspResponse {
    let leaf = parse_cert_der(&fixture("leaf.der")).unwrap();
    let issuer = parse_cert_der(&fixture("issuer.der")).unwrap();
    UnverifiedOcspResponse::new(
        issuer.rfc5280_method_one_key_identifier().unwrap().to_vec(),
        leaf.serial.clone(),
        OcspCertStatus::Good,
        1_767_656_420,
        Some(1_768_261_220),
        None,
        None,
    )
}

fn custom_response(
    issuer_key: Vec<u8>,
    serial: Vec<u8>,
    this_update: u64,
    next_update: Option<u64>,
    response_nonce: Option<Vec<u8>>,
    extensions: Option<Vec<OcspExtension>>,
) -> UnverifiedOcspResponse {
    UnverifiedOcspResponse::new(
        issuer_key,
        serial,
        OcspCertStatus::Good,
        this_update,
        next_update,
        response_nonce,
        extensions,
    )
}

#[test]
fn honest_host_response_is_accepted() {
    let bound = bind_response_to_certificates(
        honest_response(),
        &fixture("leaf.der"),
        &fixture("issuer.der"),
    )
    .unwrap();

    assert_eq!(bound.status(), OcspCertStatus::Good);
}

#[test]
fn serial_with_noncanonical_sign_padding_is_rejected() {
    let leaf = parse_cert_der(&fixture("leaf.der")).unwrap();
    let issuer = parse_cert_der(&fixture("issuer.der")).unwrap();
    let mut serial = leaf.serial.clone();
    serial.insert(0, 0);
    let response = custom_response(
        issuer.rfc5280_method_one_key_identifier().unwrap().to_vec(),
        serial,
        1_767_656_420,
        Some(1_768_261_220),
        None,
        None,
    );

    assert_eq!(
        bind_response_to_certificates(response, &fixture("leaf.der"), &fixture("issuer.der"))
            .unwrap_err(),
        OcspError::InvalidResponse
    );
}

#[test]
fn response_for_another_serial_is_rejected() {
    let issuer = parse_cert_der(&fixture("issuer.der")).unwrap();
    let response = custom_response(
        issuer.rfc5280_method_one_key_identifier().unwrap().to_vec(),
        vec![0x7F, 0x7F],
        1_767_656_420,
        Some(1_768_261_220),
        None,
        None,
    );

    assert_eq!(
        bind_response_to_certificates(response, &fixture("leaf.der"), &fixture("issuer.der"))
            .unwrap_err(),
        OcspError::InvalidResponse
    );
}

#[test]
fn response_for_another_issuer_key_is_rejected() {
    let leaf = parse_cert_der(&fixture("leaf.der")).unwrap();
    let response = custom_response(
        vec![0xAB; 20],
        leaf.serial.clone(),
        1_767_656_420,
        Some(1_768_261_220),
        None,
        None,
    );

    assert_eq!(
        bind_response_to_certificates(response, &fixture("leaf.der"), &fixture("issuer.der"))
            .unwrap_err(),
        OcspError::InvalidResponse
    );
}

#[test]
fn issuer_that_did_not_issue_certificate_is_rejected() {
    let leaf = parse_cert_der(&fixture("leaf.der")).unwrap();
    let root = parse_cert_der(&fixture("root.der")).unwrap();
    let response = custom_response(
        root.rfc5280_method_one_key_identifier().unwrap().to_vec(),
        leaf.serial.clone(),
        1_767_656_420,
        Some(1_768_261_220),
        None,
        None,
    );

    assert_eq!(
        bind_response_to_certificates(response, &fixture("leaf.der"), &fixture("root.der"))
            .unwrap_err(),
        OcspError::InvalidResponse
    );
}

#[test]
fn inverted_or_zero_validity_window_is_rejected() {
    let leaf = parse_cert_der(&fixture("leaf.der")).unwrap();
    let issuer = parse_cert_der(&fixture("issuer.der")).unwrap();
    let inverted = custom_response(
        issuer.rfc5280_method_one_key_identifier().unwrap().to_vec(),
        leaf.serial.clone(),
        100,
        Some(99),
        None,
        None,
    );
    assert_eq!(
        bind_response_to_certificates(inverted, &fixture("leaf.der"), &fixture("issuer.der"))
            .unwrap_err(),
        OcspError::InvalidResponse
    );

    let zero = custom_response(
        issuer.rfc5280_method_one_key_identifier().unwrap().to_vec(),
        leaf.serial.clone(),
        0,
        Some(1),
        None,
        None,
    );
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

#[test]
fn host_response_nonce_must_match_request_nonce() {
    let leaf = parse_cert_der(&fixture("leaf.der")).unwrap();
    let issuer = parse_cert_der(&fixture("issuer.der")).unwrap();
    let response = custom_response(
        issuer.rfc5280_method_one_key_identifier().unwrap().to_vec(),
        leaf.serial.clone(),
        1_767_656_420,
        Some(1_768_261_220),
        Some(vec![1, 2, 3, 4]),
        None,
    );
    assert!(bind_response_to_certificates_with_nonce(
        response.clone(),
        &fixture("leaf.der"),
        &fixture("issuer.der"),
        Some(&[1, 2, 3, 4]),
    )
    .is_ok());
    assert_eq!(
        bind_response_to_certificates_with_nonce(
            response,
            &fixture("leaf.der"),
            &fixture("issuer.der"),
            Some(&[1, 2, 3, 5]),
        )
        .unwrap_err(),
        OcspError::InvalidResponse
    );
}

#[test]
fn unknown_critical_host_response_extension_is_rejected() {
    let leaf = parse_cert_der(&fixture("leaf.der")).unwrap();
    let issuer = parse_cert_der(&fixture("issuer.der")).unwrap();
    let response = custom_response(
        issuer.rfc5280_method_one_key_identifier().unwrap().to_vec(),
        leaf.serial.clone(),
        1_767_656_420,
        Some(1_768_261_220),
        None,
        Some(vec![OcspExtension {
            oid: "1.2.3.4".to_owned(),
            critical: true,
            value: Vec::new(),
        }]),
    );

    assert_eq!(
        bind_response_to_certificates(response, &fixture("leaf.der"), &fixture("issuer.der"))
            .unwrap_err(),
        OcspError::InvalidResponse
    );
}
