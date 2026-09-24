// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(missing_docs, clippy::unwrap_used)]
//! Test coverage for this crate.

use openssl::{
    asn1::Asn1Time,
    bn::BigNum,
    hash::MessageDigest,
    nid::Nid,
    pkey::{PKey, Private},
    rsa::Rsa,
    x509::{
        extension::{AuthorityKeyIdentifier, BasicConstraints, KeyUsage, SubjectKeyIdentifier},
        X509Builder, X509NameBuilder, X509,
    },
};
use reallyme_trust_x509::{
    parse_cert_der, verify_chain_signatures_pure_rust, PureRustSignatureVerifier, X509Chain,
    X509Error, X509ResourceLimit, X509SignatureFailure, MAX_X509_CHAIN_CERTIFICATES,
};

fn make_name(cn: &str) -> openssl::x509::X509Name {
    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_nid(Nid::COMMONNAME, cn).unwrap();
    name.build()
}

fn set_serial(builder: &mut X509Builder, value: u32) {
    let serial = BigNum::from_u32(value).unwrap().to_asn1_integer().unwrap();
    builder.set_serial_number(&serial).unwrap();
}

fn gen_key() -> PKey<Private> {
    PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap()
}

fn build_root(cn: &str) -> (X509, PKey<Private>) {
    let key = gen_key();
    let mut builder = X509Builder::new().unwrap();
    builder.set_version(2).unwrap();
    set_serial(&mut builder, 1);
    let name = make_name(cn);
    builder.set_subject_name(&name).unwrap();
    builder.set_issuer_name(&name).unwrap();
    builder.set_pubkey(&key).unwrap();
    builder
        .set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    builder
        .set_not_after(&Asn1Time::days_from_now(365).unwrap())
        .unwrap();
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
    let skid = SubjectKeyIdentifier::new()
        .build(&builder.x509v3_context(None, None))
        .unwrap();
    builder.append_extension(skid).unwrap();
    let akid = AuthorityKeyIdentifier::new()
        .keyid(true)
        .issuer(true)
        .build(&builder.x509v3_context(None, None))
        .unwrap();
    builder.append_extension(akid).unwrap();
    builder.sign(&key, MessageDigest::sha256()).unwrap();

    (builder.build(), key)
}

fn build_leaf(cn: &str, issuer: &X509, issuer_key: &PKey<Private>, serial: u32) -> X509 {
    let key = gen_key();
    let mut builder = X509Builder::new().unwrap();
    builder.set_version(2).unwrap();
    set_serial(&mut builder, serial);
    let subject = make_name(cn);
    builder.set_subject_name(&subject).unwrap();
    builder.set_issuer_name(issuer.subject_name()).unwrap();
    builder.set_pubkey(&key).unwrap();
    builder
        .set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    builder
        .set_not_after(&Asn1Time::days_from_now(90).unwrap())
        .unwrap();
    builder
        .append_extension(BasicConstraints::new().critical().build().unwrap())
        .unwrap();
    builder
        .append_extension(
            KeyUsage::new()
                .critical()
                .digital_signature()
                .build()
                .unwrap(),
        )
        .unwrap();
    let skid = SubjectKeyIdentifier::new()
        .build(&builder.x509v3_context(Some(issuer), None))
        .unwrap();
    builder.append_extension(skid).unwrap();
    let akid = AuthorityKeyIdentifier::new()
        .keyid(true)
        .issuer(true)
        .build(&builder.x509v3_context(Some(issuer), None))
        .unwrap();
    builder.append_extension(akid).unwrap();
    builder.sign(issuer_key, MessageDigest::sha256()).unwrap();
    builder.build()
}

#[test]
fn pure_rust_signature_verifier_accepts_root_signed_leaf() {
    let (root, root_key) = build_root("Root");
    let leaf = build_leaf("Leaf", &root, &root_key, 100);
    let chain = X509Chain {
        certs: vec![
            parse_cert_der(&leaf.to_der().unwrap()).unwrap(),
            parse_cert_der(&root.to_der().unwrap()).unwrap(),
        ],
    };

    verify_chain_signatures_pure_rust(&chain).unwrap();
    PureRustSignatureVerifier::new()
        .verify_chain(&chain)
        .unwrap();
}

#[test]
fn pure_rust_signature_verifier_rejects_wrong_root() {
    let (root_a, root_a_key) = build_root("RootA");
    let leaf = build_leaf("Leaf", &root_a, &root_a_key, 101);
    let (root_b, _) = build_root("RootB");
    let chain = X509Chain {
        certs: vec![
            parse_cert_der(&leaf.to_der().unwrap()).unwrap(),
            parse_cert_der(&root_b.to_der().unwrap()).unwrap(),
        ],
    };

    let err = verify_chain_signatures_pure_rust(&chain).unwrap_err();

    assert_eq!(
        err,
        X509Error::SignatureFailed(X509SignatureFailure::ChainIssuerMismatch)
    );
}

#[test]
fn pure_rust_signature_verifier_rejects_wrong_root_with_same_subject_dn() {
    let (signing_root, signing_root_key) = build_root("Reused Root Name");
    let leaf = build_leaf("Reused Root Name", &signing_root, &signing_root_key, 102);
    let (configured_root, _) = build_root("Reused Root Name");
    let chain = X509Chain {
        certs: vec![
            parse_cert_der(&leaf.to_der().unwrap()).unwrap(),
            parse_cert_der(&configured_root.to_der().unwrap()).unwrap(),
        ],
    };

    // RFC 5280 §6 path validation requires cryptographic closure to the
    // configured trust anchor. Equal Subject DNs do not authenticate the
    // terminal certificate (CVE-2026-75522).
    let err = verify_chain_signatures_pure_rust(&chain).unwrap_err();

    assert_eq!(
        err,
        X509Error::SignatureFailed(X509SignatureFailure::InvalidSignature)
    );
}

#[test]
fn pure_rust_signature_verifier_rejects_certificate_chain_over_limit() {
    let (root, _root_key) = build_root("Root");
    let root_cert = parse_cert_der(&root.to_der().unwrap()).unwrap();
    let chain = X509Chain {
        certs: vec![root_cert; MAX_X509_CHAIN_CERTIFICATES + 1],
    };

    let err = verify_chain_signatures_pure_rust(&chain).unwrap_err();

    assert_eq!(
        err,
        X509Error::ResourceLimitExceeded(X509ResourceLimit::CertificateChainTooLong)
    );
}
