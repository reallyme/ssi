// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{parse_decimal_u8, parse_seconds, validate_delegated_responder_key_usage};
use identity_revocation_ocsp_core::OcspError;
use openssl::asn1::{Asn1Integer, Asn1Time};
use openssl::bn::BigNum;
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use openssl::x509::extension::{ExtendedKeyUsage, KeyUsage};
use openssl::x509::{X509NameBuilder, X509};

#[test]
fn seconds_accept_fractional_generalized_time() {
    assert_eq!(parse_seconds("20"), Some(20));
    assert_eq!(parse_seconds("20.5"), Some(20));
    assert_eq!(parse_seconds("07.123456"), Some(7));
}

#[test]
fn seconds_reject_malformed_fractions() {
    for value in ["", "20.", ".5", "20.5a", "2a", "+2", "20.-1", "20.5.1"] {
        assert_eq!(parse_seconds(value), None, "{value}");
    }
}

#[test]
fn decimal_fields_reject_signs_and_non_digits() {
    for value in ["", "+1", "-1", "1 ", "0x1", "256"] {
        assert_eq!(parse_decimal_u8(value), None, "{value}");
    }
    assert_eq!(parse_decimal_u8("09"), Some(9));
}

fn responder_certificate(digest: MessageDigest, digital_signature: bool) -> Vec<u8> {
    let key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", "OCSP responder").unwrap();
    let name = name.build();
    let mut builder = X509::builder().unwrap();
    builder.set_version(2).unwrap();
    let serial = Asn1Integer::from_bn(&BigNum::from_u32(1).unwrap()).unwrap();
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
    let mut usage = KeyUsage::new();
    usage.critical();
    if digital_signature {
        usage.digital_signature();
    } else {
        usage.key_encipherment();
    }
    builder.append_extension(usage.build().unwrap()).unwrap();
    builder
        .append_extension(
            ExtendedKeyUsage::new()
                .other("1.3.6.1.5.5.7.3.9")
                .build()
                .unwrap(),
        )
        .unwrap();
    builder.sign(&key, digest).unwrap();
    builder.build().to_der().unwrap()
}

#[test]
fn delegated_responder_rejects_sha1_certificate_signature() {
    let certificate = responder_certificate(MessageDigest::sha1(), true);

    assert_eq!(
        validate_delegated_responder_key_usage(&certificate),
        Err(OcspError::UntrustedResponder)
    );
}

#[test]
fn delegated_responder_requires_digital_signature_key_usage() {
    let certificate = responder_certificate(MessageDigest::sha256(), false);

    assert_eq!(
        validate_delegated_responder_key_usage(&certificate),
        Err(OcspError::UntrustedResponder)
    );
}
