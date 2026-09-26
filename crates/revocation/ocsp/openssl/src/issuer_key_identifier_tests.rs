// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use openssl::asn1::Asn1Time;
use openssl::bn::{BigNum, BigNumContext};
use openssl::ec::{EcGroup, EcKey, PointConversionForm};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::PKey;
use openssl::sha::sha1;
use openssl::x509::{X509Builder, X509NameBuilder};

use super::{issuer_key_identifier, subject_public_key_bits};
use identity_revocation_ocsp_core::OcspError;

#[test]
fn fallback_key_identifier_hashes_subject_public_key_bits_only() {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let ec_key = EcKey::generate(&group).unwrap();
    let mut ctx = BigNumContext::new().unwrap();
    let point = ec_key
        .public_key()
        .to_bytes(&group, PointConversionForm::UNCOMPRESSED, &mut ctx)
        .unwrap();
    let key = PKey::from_ec_key(ec_key).unwrap();

    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_nid(Nid::COMMONNAME, "No SKI Issuer")
        .unwrap();
    let name = name.build();
    let mut builder = X509Builder::new().unwrap();
    builder.set_version(2).unwrap();
    builder
        .set_serial_number(&BigNum::from_u32(7).unwrap().to_asn1_integer().unwrap())
        .unwrap();
    builder.set_subject_name(&name).unwrap();
    builder.set_issuer_name(&name).unwrap();
    builder
        .set_not_before(&Asn1Time::from_unix(1_700_000_000).unwrap())
        .unwrap();
    builder
        .set_not_after(&Asn1Time::from_unix(2_000_000_000).unwrap())
        .unwrap();
    builder.set_pubkey(&key).unwrap();
    builder.sign(&key, MessageDigest::sha256()).unwrap();
    let issuer = builder.build();
    assert!(issuer.subject_key_id().is_none());

    let spki = key.public_key_to_der().unwrap();
    assert_ne!(
        issuer_key_identifier(&issuer).unwrap(),
        sha1(&spki).to_vec(),
        "must not hash the full SubjectPublicKeyInfo"
    );
    assert_eq!(
        issuer_key_identifier(&issuer).unwrap(),
        sha1(&point).to_vec()
    );
}

#[test]
fn malformed_subject_public_key_info_is_rejected() {
    let cases: [&[u8]; 6] = [
        &[],
        &[0x31, 0x00],
        &[0x30, 0x05, 0x30, 0x00],
        &[0x30, 0x04, 0x30, 0x00, 0x03, 0x00],
        &[0x30, 0x05, 0x30, 0x00, 0x03, 0x01, 0x01],
        &[0x30, 0x84, 0xFF, 0xFF, 0xFF, 0xFF],
    ];
    for case in cases {
        assert_eq!(
            subject_public_key_bits(case),
            Err(OcspError::InvalidResponse)
        );
    }
}
