// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Tests that xmlsec FFI rejects tampered TSL signatures.
#![cfg(all(feature = "xmlsec-ffi", not(target_os = "macos")))]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use identity_trust_tsl_xmlsec::verify_tsl_xmldsig_xmlsec;
use std::io::Write;
use tempfile::NamedTempFile;

const SIGNED_TSL_XML: &str = include_str!("../../tsl-openssl/tests/fixtures/signed_tsl.xml");
const TRUST_ROOT_PEM: &[u8] = include_bytes!("../../tsl-openssl/tests/fixtures/cert.pem");

fn verification_time() -> time::OffsetDateTime {
    time::OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap()
}

#[test]
fn ffi_rejects_modified_signature_value() {
    let mut pem = NamedTempFile::new().unwrap();
    pem.write_all(TRUST_ROOT_PEM).unwrap();
    pem.flush().unwrap();

    let start = SIGNED_TSL_XML
        .find("<ds:SignatureValue>")
        .expect("fixture must contain SignatureValue")
        + "<ds:SignatureValue>".len();
    let end = SIGNED_TSL_XML[start..]
        .find("</ds:SignatureValue>")
        .expect("fixture must contain SignatureValue end")
        + start;

    let sig = &SIGNED_TSL_XML[start..end];
    assert!(!sig.is_empty(), "fixture signature must not be empty");

    // Flip one base64 character to force signature failure while keeping XML well-formed.
    let mut bytes = sig.as_bytes().to_vec();
    bytes[0] = if bytes[0] == b'A' { b'B' } else { b'A' };
    let sig2 = String::from_utf8(bytes).unwrap();

    let mutated = format!(
        "{}{}{}",
        &SIGNED_TSL_XML[..start],
        sig2,
        &SIGNED_TSL_XML[end..]
    );

    let _err =
        verify_tsl_xmldsig_xmlsec(&mutated, pem.path().to_str().unwrap(), verification_time())
            .unwrap_err();
}
