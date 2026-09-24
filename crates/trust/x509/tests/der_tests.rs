// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(missing_docs, clippy::expect_used)]
//! Tests for the bounded DER projection boundary.

use reallyme_codec::base64::base64_to_bytes;
use reallyme_trust_x509::{
    certificate_subject_public_key_info, parse_subject_public_key_info_der,
    validate_certificate_der, validate_x509_name_der, X509Error,
};

#[test]
fn certificate_projection_accepts_complete_der_and_rejects_trailing_bytes() {
    let certificate =
        base64_to_bytes(include_str!("fixtures/qwac_server_auth_cert.der.b64").trim())
            .expect("checked-in certificate fixture must be valid base64");

    assert!(validate_certificate_der(&certificate));
    let subject_public_key = certificate_subject_public_key_info(&certificate)
        .expect("checked-in certificate fixture must expose a public key");
    assert!(!subject_public_key.public_key.is_empty());

    let mut with_trailing_byte = certificate;
    with_trailing_byte.push(0);
    assert!(!validate_certificate_der(&with_trailing_byte));
}

#[test]
fn malformed_der_fails_with_the_stable_typed_error() {
    assert_eq!(
        parse_subject_public_key_info_der(&[0x30, 0x01, 0x00]),
        Err(X509Error::InvalidDer),
    );
    assert!(!validate_x509_name_der(&[]));
    assert!(!validate_x509_name_der(&[0xff]));
}
