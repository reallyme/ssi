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
//! Tests for the WASM certificate-chain signature verifier.
#![cfg(not(target_arch = "wasm32"))]

use identity_trust_wasm::WasmSignatureVerifier;
use reallyme_trust_core::SignatureVerifier;

use envelopes_x509::{parse_cert_der, X509Chain};

use openssl::{
    asn1::{Asn1Object, Asn1OctetString, Asn1Time},
    bn::BigNum,
    hash::MessageDigest,
    nid::Nid,
    pkey::{PKey, Private},
    rsa::Rsa,
    x509::{
        extension::{AuthorityKeyIdentifier, BasicConstraints, KeyUsage, SubjectKeyIdentifier},
        X509Builder, X509Extension, X509NameBuilder, X509,
    },
};

use time::OffsetDateTime;

fn make_name(cn: &str) -> openssl::x509::X509Name {
    let mut nb = X509NameBuilder::new().unwrap();
    nb.append_entry_by_nid(Nid::COMMONNAME, cn).unwrap();
    nb.build()
}

fn set_serial(b: &mut X509Builder, n: u32) {
    let bn = BigNum::from_u32(n).unwrap();
    let serial = bn.to_asn1_integer().unwrap();
    b.set_serial_number(&serial).unwrap();
}

fn gen_key() -> PKey<Private> {
    // Fast for tests: RSA 2048.
    let rsa = Rsa::generate(2048).unwrap();
    PKey::from_rsa(rsa).unwrap()
}

fn build_root(cn: &str) -> (X509, PKey<Private>) {
    let key = gen_key();
    let mut b = X509Builder::new().unwrap();

    b.set_version(2).unwrap();
    set_serial(&mut b, 1);

    let name = make_name(cn);
    b.set_subject_name(&name).unwrap();
    b.set_issuer_name(&name).unwrap();

    b.set_pubkey(&key).unwrap();
    b.set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    b.set_not_after(&Asn1Time::days_from_now(3650).unwrap())
        .unwrap();

    let bc = BasicConstraints::new().critical().ca().build().unwrap();
    b.append_extension(bc).unwrap();

    let ku = KeyUsage::new()
        .critical()
        .key_cert_sign()
        .crl_sign()
        .build()
        .unwrap();
    b.append_extension(ku).unwrap();

    let skid = SubjectKeyIdentifier::new()
        .build(&b.x509v3_context(None, None))
        .unwrap();
    b.append_extension(skid).unwrap();

    let akid = AuthorityKeyIdentifier::new()
        .keyid(true)
        .issuer(true)
        .build(&b.x509v3_context(None, None))
        .unwrap();
    b.append_extension(akid).unwrap();

    b.sign(&key, MessageDigest::sha256()).unwrap();
    (b.build(), key)
}

fn build_intermediate(
    cn: &str,
    issuer: &X509,
    issuer_key: &PKey<Private>,
) -> (X509, PKey<Private>) {
    let key = gen_key();
    let mut b = X509Builder::new().unwrap();

    b.set_version(2).unwrap();
    set_serial(&mut b, 2);

    let subject = make_name(cn);
    b.set_subject_name(&subject).unwrap();
    b.set_issuer_name(issuer.subject_name()).unwrap();

    b.set_pubkey(&key).unwrap();
    b.set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    b.set_not_after(&Asn1Time::days_from_now(1825).unwrap())
        .unwrap();

    let bc = BasicConstraints::new()
        .critical()
        .ca()
        .pathlen(0)
        .build()
        .unwrap();
    b.append_extension(bc).unwrap();

    let ku = KeyUsage::new()
        .critical()
        .key_cert_sign()
        .crl_sign()
        .build()
        .unwrap();
    b.append_extension(ku).unwrap();

    let skid = SubjectKeyIdentifier::new()
        .build(&b.x509v3_context(Some(issuer), None))
        .unwrap();
    b.append_extension(skid).unwrap();

    let akid = AuthorityKeyIdentifier::new()
        .keyid(true)
        .issuer(true)
        .build(&b.x509v3_context(Some(issuer), None))
        .unwrap();
    b.append_extension(akid).unwrap();

    b.sign(issuer_key, MessageDigest::sha256()).unwrap();
    (b.build(), key)
}

fn build_leaf(cn: &str, issuer: &X509, issuer_key: &PKey<Private>, serial: u32) -> X509 {
    let key = gen_key();
    let mut b = X509Builder::new().unwrap();

    b.set_version(2).unwrap();
    set_serial(&mut b, serial);

    let subject = make_name(cn);
    b.set_subject_name(&subject).unwrap();
    b.set_issuer_name(issuer.subject_name()).unwrap();

    b.set_pubkey(&key).unwrap();
    b.set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    b.set_not_after(&Asn1Time::days_from_now(397).unwrap())
        .unwrap();

    let bc = BasicConstraints::new().critical().build().unwrap();
    b.append_extension(bc).unwrap();

    let ku = KeyUsage::new()
        .critical()
        .digital_signature()
        .build()
        .unwrap();
    b.append_extension(ku).unwrap();

    let skid = SubjectKeyIdentifier::new()
        .build(&b.x509v3_context(Some(issuer), None))
        .unwrap();
    b.append_extension(skid).unwrap();

    let akid = AuthorityKeyIdentifier::new()
        .keyid(true)
        .issuer(true)
        .build(&b.x509v3_context(Some(issuer), None))
        .unwrap();
    b.append_extension(akid).unwrap();

    b.sign(issuer_key, MessageDigest::sha256()).unwrap();
    b.build()
}

#[test]
fn verifies_root_signed_leaf() {
    let (root, root_key) = build_root("CN=Root");
    let leaf = build_leaf("CN=Leaf", &root, &root_key, 100);

    let root_env = parse_cert_der(&root.to_der().unwrap()).unwrap();
    let leaf_env = parse_cert_der(&leaf.to_der().unwrap()).unwrap();

    let chain = X509Chain {
        certs: vec![leaf_env, root_env],
    };

    let verifier = WasmSignatureVerifier::new();
    verifier
        .verify_chain(&chain, OffsetDateTime::now_utc())
        .unwrap();
}

#[test]
fn verifies_intermediate_chain() {
    let (root, root_key) = build_root("CN=Root");
    let (intermediate, inter_key) = build_intermediate("CN=Intermediate", &root, &root_key);
    let leaf = build_leaf("CN=Leaf", &intermediate, &inter_key, 101);

    let root_env = parse_cert_der(&root.to_der().unwrap()).unwrap();
    let int_env = parse_cert_der(&intermediate.to_der().unwrap()).unwrap();
    let leaf_env = parse_cert_der(&leaf.to_der().unwrap()).unwrap();

    let chain = X509Chain {
        certs: vec![leaf_env, int_env, root_env],
    };

    let verifier = WasmSignatureVerifier::new();
    verifier
        .verify_chain(&chain, OffsetDateTime::now_utc())
        .unwrap();
}

#[test]
fn rejects_wrong_root() {
    let (root_a, root_a_key) = build_root("CN=RootA");
    let leaf = build_leaf("CN=Leaf", &root_a, &root_a_key, 102);

    let (root_b, _root_b_key) = build_root("CN=RootB");

    let leaf_env = parse_cert_der(&leaf.to_der().unwrap()).unwrap();
    let wrong_root_env = parse_cert_der(&root_b.to_der().unwrap()).unwrap();

    let chain = X509Chain {
        certs: vec![leaf_env, wrong_root_env],
    };

    let verifier = WasmSignatureVerifier::new();
    let err = verifier
        .verify_chain(&chain, OffsetDateTime::now_utc())
        .unwrap_err();

    assert!(matches!(
        err,
        reallyme_trust_core::SignatureVerifyError::InvalidSignature
    ));
}

#[test]
fn name_constrained_root_fails_closed_as_unsupported() {
    // NameConstraints { permittedSubtrees { dNSName "example.com" } }.
    const NAME_CONSTRAINTS_DER: &[u8] = &[
        0x30, 0x11, 0xa0, 0x0f, 0x30, 0x0d, 0x82, 0x0b, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
        b'.', b'c', b'o', b'm',
    ];
    let key = gen_key();
    let mut b = X509Builder::new().unwrap();
    b.set_version(2).unwrap();
    set_serial(&mut b, 9);
    let name = make_name("Constrained Root");
    b.set_subject_name(&name).unwrap();
    b.set_issuer_name(&name).unwrap();
    b.set_pubkey(&key).unwrap();
    b.set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    b.set_not_after(&Asn1Time::days_from_now(365).unwrap())
        .unwrap();
    b.append_extension(BasicConstraints::new().critical().ca().build().unwrap())
        .unwrap();
    b.append_extension(
        KeyUsage::new()
            .critical()
            .key_cert_sign()
            .crl_sign()
            .build()
            .unwrap(),
    )
    .unwrap();
    let skid = SubjectKeyIdentifier::new()
        .build(&b.x509v3_context(None, None))
        .unwrap();
    b.append_extension(skid).unwrap();
    let oid = Asn1Object::from_str("2.5.29.30").unwrap();
    let value = Asn1OctetString::new_from_bytes(NAME_CONSTRAINTS_DER).unwrap();
    b.append_extension(X509Extension::new_from_der(&oid, true, &value).unwrap())
        .unwrap();
    b.sign(&key, MessageDigest::sha256()).unwrap();
    let root = b.build();
    let leaf = build_leaf("CN=Leaf", &root, &key, 103);

    let chain = X509Chain {
        certs: vec![
            parse_cert_der(&leaf.to_der().unwrap()).unwrap(),
            parse_cert_der(&root.to_der().unwrap()).unwrap(),
        ],
    };

    let err = WasmSignatureVerifier::new()
        .verify_chain(&chain, OffsetDateTime::now_utc())
        .unwrap_err();

    assert!(matches!(
        err,
        reallyme_trust_core::SignatureVerifyError::UnsupportedAlgorithm
    ));
}
