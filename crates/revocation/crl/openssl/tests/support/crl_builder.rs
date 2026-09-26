// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Minimal DER builder for signed test CRLs with arbitrary extensions.

use openssl::asn1::Asn1Time;
use openssl::bn::BigNum;
use openssl::ec::{EcGroup, EcKey};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private};
use openssl::sign::Signer;
use openssl::x509::extension::{BasicConstraints, KeyUsage, SubjectKeyIdentifier};
use openssl::x509::{X509Builder, X509NameBuilder, X509};

const TAG_BOOLEAN: u8 = 0x01;
const TAG_INTEGER: u8 = 0x02;
const TAG_BIT_STRING: u8 = 0x03;
const TAG_OCTET_STRING: u8 = 0x04;
const TAG_OID: u8 = 0x06;
const TAG_UTC_TIME: u8 = 0x17;
const TAG_SEQUENCE: u8 = 0x30;
const TAG_CRL_EXTENSIONS: u8 = 0xA0;
const ECDSA_WITH_SHA256_OID: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02];

pub const OID_CRL_NUMBER: &[u8] = &[0x55, 0x1D, 0x14];
pub const OID_REASON_CODE: &[u8] = &[0x55, 0x1D, 0x15];
pub const OID_AUTHORITY_KEY_IDENTIFIER: &[u8] = &[0x55, 0x1D, 0x23];
pub const OID_DELTA_CRL_INDICATOR: &[u8] = &[0x55, 0x1D, 0x1B];
pub const OID_ISSUING_DISTRIBUTION_POINT: &[u8] = &[0x55, 0x1D, 0x1C];
pub const OID_CERTIFICATE_ISSUER: &[u8] = &[0x55, 0x1D, 0x1D];
/// 1.3.6.1.4.1.99999.1 (private arc, not understood by the parser).
pub const OID_UNKNOWN: &[u8] = &[0x2B, 0x06, 0x01, 0x04, 0x01, 0x86, 0x8D, 0x1F, 0x01];

pub struct TestCa {
    pub cert: X509,
    pub key: PKey<Private>,
}

pub fn test_ca(common_name: &str) -> TestCa {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let key = PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap();

    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_nid(Nid::COMMONNAME, common_name)
        .unwrap();
    let name = name.build();

    let mut builder = X509Builder::new().unwrap();
    builder.set_version(2).unwrap();
    let serial = BigNum::from_u32(1).unwrap().to_asn1_integer().unwrap();
    builder.set_serial_number(&serial).unwrap();
    builder.set_subject_name(&name).unwrap();
    builder.set_issuer_name(&name).unwrap();
    builder
        .set_not_before(&Asn1Time::from_unix(1_700_000_000).unwrap())
        .unwrap();
    builder
        .set_not_after(&Asn1Time::from_unix(2_100_000_000).unwrap())
        .unwrap();
    builder.set_pubkey(&key).unwrap();
    builder
        .append_extension(BasicConstraints::new().critical().ca().build().unwrap())
        .unwrap();
    builder
        .append_extension(
            KeyUsage::new()
                .critical()
                .key_cert_sign()
                .crl_sign()
                .build()
                .unwrap(),
        )
        .unwrap();
    let ski = SubjectKeyIdentifier::new()
        .build(&builder.x509v3_context(None, None))
        .unwrap();
    builder.append_extension(ski).unwrap();
    builder.sign(&key, MessageDigest::sha256()).unwrap();

    TestCa {
        cert: builder.build(),
        key,
    }
}

#[derive(Clone)]
pub struct Extension {
    pub oid: &'static [u8],
    pub critical: bool,
    pub value: Vec<u8>,
}

impl Extension {
    pub fn new(oid: &'static [u8], critical: bool, value: Vec<u8>) -> Self {
        Self {
            oid,
            critical,
            value,
        }
    }

    pub fn crl_number() -> Self {
        Self::new(OID_CRL_NUMBER, false, integer(&[1]))
    }
}

#[derive(Clone)]
pub struct Entry {
    pub serial: Vec<u8>,
    pub extensions: Vec<Extension>,
}

#[derive(Clone)]
pub struct CrlSpec {
    pub issuer_name_der: Option<Vec<u8>>,
    pub this_update: i64,
    pub next_update: Option<i64>,
    pub entries: Vec<Entry>,
    pub extensions: Vec<Extension>,
}

pub const THIS_UPDATE: i64 = 1_767_571_200;
pub const NEXT_UPDATE: i64 = THIS_UPDATE + 7 * 86_400;

impl Default for CrlSpec {
    fn default() -> Self {
        Self {
            issuer_name_der: None,
            this_update: THIS_UPDATE,
            next_update: Some(NEXT_UPDATE),
            entries: Vec::new(),
            extensions: vec![Extension::crl_number()],
        }
    }
}

fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let len = content.len();
    if len < 0x80 {
        out.push(u8::try_from(len).unwrap());
    } else {
        let bytes = u32::try_from(len).unwrap().to_be_bytes();
        let first = bytes.iter().position(|b| *b != 0).unwrap();
        let significant = &bytes[first..];
        out.push(0x80 | u8::try_from(significant.len()).unwrap());
        out.extend_from_slice(significant);
    }
    out.extend_from_slice(content);
    out
}

fn concat(parts: &[Vec<u8>]) -> Vec<u8> {
    parts.iter().flatten().copied().collect()
}

pub fn integer(magnitude: &[u8]) -> Vec<u8> {
    let mut content = Vec::new();
    if magnitude.first().is_some_and(|b| b & 0x80 != 0) {
        content.push(0);
    }
    content.extend_from_slice(magnitude);
    tlv(TAG_INTEGER, &content)
}

fn utc_time(unix: i64) -> Vec<u8> {
    let t = time::OffsetDateTime::from_unix_timestamp(unix).unwrap();
    let text = format!(
        "{:02}{:02}{:02}{:02}{:02}{:02}Z",
        t.year() % 100,
        u8::from(t.month()),
        t.day(),
        t.hour(),
        t.minute(),
        t.second()
    );
    tlv(TAG_UTC_TIME, text.as_bytes())
}

fn encode_extension(extension: &Extension) -> Vec<u8> {
    let mut parts = vec![tlv(TAG_OID, extension.oid)];
    if extension.critical {
        parts.push(tlv(TAG_BOOLEAN, &[0xFF]));
    }
    parts.push(tlv(TAG_OCTET_STRING, &extension.value));
    tlv(TAG_SEQUENCE, &concat(&parts))
}

fn encode_extensions(extensions: &[Extension]) -> Vec<u8> {
    let encoded: Vec<Vec<u8>> = extensions.iter().map(encode_extension).collect();
    tlv(TAG_SEQUENCE, &concat(&encoded))
}

pub fn build_crl(ca: &TestCa, spec: &CrlSpec) -> Vec<u8> {
    let algorithm = tlv(TAG_SEQUENCE, &tlv(TAG_OID, ECDSA_WITH_SHA256_OID));
    let issuer = spec
        .issuer_name_der
        .clone()
        .unwrap_or_else(|| ca.cert.subject_name().to_der().unwrap());

    let mut tbs_parts = vec![
        integer(&[1]),
        algorithm.clone(),
        issuer,
        utc_time(spec.this_update),
    ];
    if let Some(next) = spec.next_update {
        tbs_parts.push(utc_time(next));
    }
    if !spec.entries.is_empty() {
        let entries: Vec<Vec<u8>> = spec
            .entries
            .iter()
            .map(|entry| {
                let mut parts = vec![integer(&entry.serial), utc_time(spec.this_update)];
                if !entry.extensions.is_empty() {
                    parts.push(encode_extensions(&entry.extensions));
                }
                tlv(TAG_SEQUENCE, &concat(&parts))
            })
            .collect();
        tbs_parts.push(tlv(TAG_SEQUENCE, &concat(&entries)));
    }
    if !spec.extensions.is_empty() {
        tbs_parts.push(tlv(
            TAG_CRL_EXTENSIONS,
            &encode_extensions(&spec.extensions),
        ));
    }
    let tbs = tlv(TAG_SEQUENCE, &concat(&tbs_parts));

    let mut signer = Signer::new(MessageDigest::sha256(), &ca.key).unwrap();
    let signature = signer.sign_oneshot_to_vec(&tbs).unwrap();
    let mut bit_string = vec![0];
    bit_string.extend_from_slice(&signature);

    tlv(
        TAG_SEQUENCE,
        &concat(&[tbs, algorithm, tlv(TAG_BIT_STRING, &bit_string)]),
    )
}

pub fn name_der(common_name: &str) -> Vec<u8> {
    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_nid(Nid::COMMONNAME, common_name)
        .unwrap();
    name.build().to_der().unwrap()
}
