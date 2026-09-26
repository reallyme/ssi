// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(missing_docs, clippy::unwrap_used)]
//! Test coverage for this crate.

use openssl::{
    asn1::{Asn1Object, Asn1OctetString, Asn1Time, Asn1Type},
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

/// RFC 5280 id-ce-nameConstraints.
const OID_NAME_CONSTRAINTS: &str = "2.5.29.30";
/// RFC 5280 id-ce-policyConstraints.
const OID_POLICY_CONSTRAINTS: &str = "2.5.29.36";
/// RFC 5280 id-ce-inhibitAnyPolicy.
const OID_INHIBIT_ANY_POLICY: &str = "2.5.29.54";
/// NameConstraints { permittedSubtrees { dNSName "example.com" } }.
const NAME_CONSTRAINTS_DER: &[u8] = &[
    0x30, 0x11, 0xa0, 0x0f, 0x30, 0x0d, 0x82, 0x0b, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.',
    b'c', b'o', b'm',
];
/// PolicyConstraints { requireExplicitPolicy 0 }.
const POLICY_CONSTRAINTS_DER: &[u8] = &[0x30, 0x03, 0x80, 0x01, 0x00];
/// InhibitAnyPolicy SkipCerts 0.
const INHIBIT_ANY_POLICY_DER: &[u8] = &[0x02, 0x01, 0x00];
/// sha256WithRSAEncryption AlgorithmIdentifier with NULL parameters.
const SHA256_WITH_RSA_ALGORITHM_IDENTIFIER: &[u8] = &[
    0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00,
];

fn raw_extension(oid: &str, critical: bool, value: &[u8]) -> X509Extension {
    let oid = Asn1Object::from_str(oid).unwrap();
    let value = Asn1OctetString::new_from_bytes(value).unwrap();
    X509Extension::new_from_der(&oid, critical, &value).unwrap()
}

/// Build a self-signed CA root carrying one additional extension.
fn build_root_with_extension(cn: &str, extension: X509Extension) -> (X509, PKey<Private>) {
    let key = gen_key();
    let mut builder = X509Builder::new().unwrap();
    builder.set_version(2).unwrap();
    set_serial(&mut builder, 7);
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
    builder.append_extension(extension).unwrap();
    builder.sign(&key, MessageDigest::sha256()).unwrap();
    (builder.build(), key)
}

fn parsed_chain(certificates: &[&X509]) -> X509Chain {
    X509Chain {
        certs: certificates
            .iter()
            .map(|certificate| parse_cert_der(&certificate.to_der().unwrap()).unwrap())
            .collect(),
    }
}

#[test]
fn pure_rust_lane_rejects_unprocessed_path_constraints_critical_or_not() {
    let cases = [
        (OID_NAME_CONSTRAINTS, NAME_CONSTRAINTS_DER, true),
        (OID_NAME_CONSTRAINTS, NAME_CONSTRAINTS_DER, false),
        (OID_POLICY_CONSTRAINTS, POLICY_CONSTRAINTS_DER, true),
        (OID_POLICY_CONSTRAINTS, POLICY_CONSTRAINTS_DER, false),
        (OID_INHIBIT_ANY_POLICY, INHIBIT_ANY_POLICY_DER, true),
        (OID_INHIBIT_ANY_POLICY, INHIBIT_ANY_POLICY_DER, false),
    ];

    for (oid, value, critical) in cases {
        let (root, root_key) =
            build_root_with_extension("Constrained Root", raw_extension(oid, critical, value));
        let leaf = build_leaf("Leaf", &root, &root_key, 200);
        let chain = parsed_chain(&[&leaf, &root]);

        let err = verify_chain_signatures_pure_rust(&chain).unwrap_err();

        assert_eq!(
            err,
            X509Error::SignatureFailed(X509SignatureFailure::UnsupportedPathConstraint),
            "oid {oid} critical {critical}"
        );
    }
}

#[test]
fn pure_rust_lane_rejects_mismatched_signature_algorithm_identifiers() {
    let (root, root_key) = build_root("Root");
    let leaf = build_leaf("Leaf", &root, &root_key, 201);
    let mut leaf_der = leaf.to_der().unwrap();

    // Replace the NULL parameters of the outer signatureAlgorithm, which the
    // signature does not cover, with an empty OCTET STRING of equal length.
    // The TBS bytes and signature are untouched, so without the RFC 5280
    // Section 4.1.1.2 comparison the certificate would still verify.
    let outer_offset = leaf_der
        .windows(SHA256_WITH_RSA_ALGORITHM_IDENTIFIER.len())
        .rposition(|window| window == SHA256_WITH_RSA_ALGORITHM_IDENTIFIER)
        .unwrap();
    let null_tag_offset = outer_offset + SHA256_WITH_RSA_ALGORITHM_IDENTIFIER.len() - 2;
    leaf_der[null_tag_offset] = 0x04;

    let chain = X509Chain {
        certs: vec![
            parse_cert_der(&leaf_der).unwrap(),
            parse_cert_der(&root.to_der().unwrap()).unwrap(),
        ],
    };

    let err = verify_chain_signatures_pure_rust(&chain).unwrap_err();

    assert_eq!(
        err,
        X509Error::SignatureFailed(X509SignatureFailure::AlgorithmIdentifierMismatch)
    );
}

#[test]
fn pure_rust_lane_rejects_issuer_name_that_only_matches_by_display_string() {
    let (root, root_key) = build_root("Colliding Root");
    // Same attribute and characters under the other string type than the
    // root's encoding: the rendered strings collide, the DER differs.
    let root_der = root.to_der().unwrap();
    let common_name = b"Colliding Root";
    let common_name_offset = root_der
        .windows(common_name.len())
        .position(|window| window == common_name)
        .unwrap();
    let root_string_tag = root_der[common_name_offset - 2];
    let alternate_type = if root_string_tag == 0x0c {
        Asn1Type::PRINTABLESTRING
    } else {
        Asn1Type::UTF8STRING
    };
    let mut alternate_name = X509NameBuilder::new().unwrap();
    alternate_name
        .append_entry_by_nid_with_type(Nid::COMMONNAME, "Colliding Root", alternate_type)
        .unwrap();
    let alternate_name = alternate_name.build();

    let key = gen_key();
    let mut builder = X509Builder::new().unwrap();
    builder.set_version(2).unwrap();
    set_serial(&mut builder, 202);
    builder.set_subject_name(&make_name("Leaf")).unwrap();
    builder.set_issuer_name(&alternate_name).unwrap();
    builder.set_pubkey(&key).unwrap();
    builder
        .set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    builder
        .set_not_after(&Asn1Time::days_from_now(90).unwrap())
        .unwrap();
    builder.sign(&root_key, MessageDigest::sha256()).unwrap();
    let leaf = builder.build();

    let chain = parsed_chain(&[&leaf, &root]);
    let (leaf_cert, root_cert) = (&chain.certs[0], &chain.certs[1]);
    assert_eq!(leaf_cert.issuer, root_cert.subject);
    assert_ne!(leaf_cert.issuer_der, root_cert.subject_der);

    let err = verify_chain_signatures_pure_rust(&chain).unwrap_err();

    assert_eq!(
        err,
        X509Error::SignatureFailed(X509SignatureFailure::ChainIssuerMismatch)
    );
}

#[test]
fn parsed_certificate_matches_its_rfc5280_method_one_key_identifier() {
    let (root, _root_key) = build_root("Root");
    let parsed = parse_cert_der(&root.to_der().unwrap()).unwrap();
    // OpenSSL derives the SubjectKeyIdentifier extension with RFC 5280
    // method 1, so the computed identifier must equal it for this issuer.
    let extension_value = parsed.subject_key_identifier.clone().unwrap();

    assert!(parsed.matches_key_identifier(&extension_value));
}
