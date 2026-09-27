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
use openssl::asn1::{Asn1Integer, Asn1Time};
use openssl::bn::BigNum;
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use openssl::x509::extension::{ExtendedKeyUsage, KeyUsage};
use openssl::x509::{X509NameBuilder, X509};

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

fn der_tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut encoded = vec![tag];
    if content.len() < 128 {
        encoded.push(u8::try_from(content.len()).unwrap());
    } else {
        let length = content.len().to_be_bytes();
        let first = length.iter().position(|byte| *byte != 0).unwrap();
        let length = &length[first..];
        encoded.push(0x80 | u8::try_from(length.len()).unwrap());
        encoded.extend_from_slice(length);
    }
    encoded.extend_from_slice(content);
    encoded
}

fn take_der_tlv(input: &[u8], expected_tag: u8) -> (&[u8], &[u8], &[u8]) {
    assert_eq!(input.first(), Some(&expected_tag));
    let first_length = input[1];
    let (header_len, content_len) = if first_length & 0x80 == 0 {
        (2, usize::from(first_length))
    } else {
        let octets = usize::from(first_length & 0x7f);
        let mut content_len = 0_usize;
        for byte in &input[2..2 + octets] {
            content_len = content_len.checked_mul(256).unwrap();
            content_len = content_len.checked_add(usize::from(*byte)).unwrap();
        }
        (2 + octets, content_len)
    };
    let encoded_len = header_len.checked_add(content_len).unwrap();
    (
        &input[..encoded_len],
        &input[header_len..encoded_len],
        &input[encoded_len..],
    )
}

fn append_embedded_certificate(response: &[u8], certificate: &[u8]) -> Vec<u8> {
    let (_, response_content, outer_rest) = take_der_tlv(response, 0x30);
    assert!(outer_rest.is_empty());
    let (status, _, response_content) = take_der_tlv(response_content, 0x0a);
    let (_, explicit_content, response_rest) = take_der_tlv(response_content, 0xa0);
    assert!(response_rest.is_empty());
    let (_, response_bytes_content, explicit_rest) = take_der_tlv(explicit_content, 0x30);
    assert!(explicit_rest.is_empty());
    let (response_type, _, response_bytes_content) = take_der_tlv(response_bytes_content, 0x06);
    let (_, basic_der, response_bytes_rest) = take_der_tlv(response_bytes_content, 0x04);
    assert!(response_bytes_rest.is_empty());
    let (_, basic_content, basic_der_rest) = take_der_tlv(basic_der, 0x30);
    assert!(basic_der_rest.is_empty());
    let (response_data, _, basic_content) = take_der_tlv(basic_content, 0x30);
    let (signature_algorithm, _, basic_content) = take_der_tlv(basic_content, 0x30);
    let (signature, _, basic_content) = take_der_tlv(basic_content, 0x03);
    let (_, certificate_sequence_der, basic_rest) = take_der_tlv(basic_content, 0xa0);
    assert!(basic_rest.is_empty());
    let (_, certificate_sequence, sequence_rest) = take_der_tlv(certificate_sequence_der, 0x30);
    assert!(sequence_rest.is_empty());

    let mut certificates = certificate_sequence.to_vec();
    certificates.extend_from_slice(certificate);
    let certificates = der_tlv(0xa0, &der_tlv(0x30, &certificates));
    let mut rebuilt_basic_content = Vec::new();
    rebuilt_basic_content.extend_from_slice(response_data);
    rebuilt_basic_content.extend_from_slice(signature_algorithm);
    rebuilt_basic_content.extend_from_slice(signature);
    rebuilt_basic_content.extend_from_slice(&certificates);
    let rebuilt_basic = der_tlv(0x30, &rebuilt_basic_content);

    let mut rebuilt_response_bytes = response_type.to_vec();
    rebuilt_response_bytes.extend_from_slice(&der_tlv(0x04, &rebuilt_basic));
    let response_bytes = der_tlv(0xa0, &der_tlv(0x30, &rebuilt_response_bytes));
    let mut rebuilt_response = status.to_vec();
    rebuilt_response.extend_from_slice(&response_bytes);
    der_tlv(0x30, &rebuilt_response)
}

fn embedded_responder_without_digital_signature() -> Vec<u8> {
    let key = PKey::from_rsa(Rsa::generate(2_048).unwrap()).unwrap();
    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", "OCSP responder without signing usage")
        .unwrap();
    let name = name.build();
    let mut builder = X509::builder().unwrap();
    builder.set_version(2).unwrap();
    let serial = Asn1Integer::from_bn(&BigNum::from_u32(9).unwrap()).unwrap();
    builder.set_serial_number(&serial).unwrap();
    builder.set_subject_name(&name).unwrap();
    builder.set_issuer_name(&name).unwrap();
    builder.set_pubkey(&key).unwrap();
    builder
        .set_not_before(Asn1Time::days_from_now(0).unwrap().as_ref())
        .unwrap();
    builder
        .set_not_after(Asn1Time::days_from_now(1).unwrap().as_ref())
        .unwrap();
    builder
        .append_extension(KeyUsage::new().key_encipherment().build().unwrap())
        .unwrap();
    builder
        .append_extension(
            ExtendedKeyUsage::new()
                .other("1.3.6.1.5.5.7.3.9")
                .build()
                .unwrap(),
        )
        .unwrap();
    builder.sign(&key, MessageDigest::sha256()).unwrap();
    builder.build().to_der().unwrap()
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
fn embedded_responder_certificates_require_digital_signature_key_usage() {
    let (response, leaf, issuer, root) = fixture_certs();
    // Certificates are outside the signed ResponseData. Add a second,
    // otherwise-unused OCSP responder so OpenSSL can still verify the original
    // signer; the policy layer must independently screen every embedded cert.
    let malformed =
        append_embedded_certificate(&response, &embedded_responder_without_digital_signature());

    assert_eq!(
        parse_ocsp_response_der(&malformed, &leaf, &issuer, &[root], FIXTURE_NOW).unwrap_err(),
        OcspError::UntrustedResponder
    );
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
