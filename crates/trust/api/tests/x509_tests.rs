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
//! Tests for X.509 trust API parsing and metadata extraction.

use identity_credential_trust_api::{
    extract_certificate_metadata_der, parse_x509_chain_der, validate_certificate_chain_der,
    validate_trust_anchor_der, TrustAnchorsDer, TrustApiError, TrustDecisionFailure,
    TrustDecisionOutcome, X509CertificateDer, X509ChainDer,
};
use openssl::{
    asn1::Asn1Time,
    bn::BigNum,
    hash::MessageDigest,
    nid::Nid,
    pkey::{PKey, Private},
    rsa::Rsa,
    x509::{
        extension::{AuthorityKeyIdentifier, BasicConstraints, KeyUsage, SubjectKeyIdentifier},
        X509Builder, X509NameBuilder,
    },
};
use reallyme_codec::base64::base64_to_bytes;
use zeroize::Zeroize;

const QWAC_CERTIFICATE_DER_BASE64: &str =
    include_str!("../../x509/tests/fixtures/qwac_server_auth_cert.der.b64");

fn qwac_certificate_der() -> Vec<u8> {
    base64_to_bytes(QWAC_CERTIFICATE_DER_BASE64.trim())
        .expect("repository certificate fixture must be valid base64")
}

fn certificate_name(common_name: &str) -> openssl::x509::X509Name {
    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_nid(Nid::COMMONNAME, common_name)
        .unwrap();
    name.build()
}

fn signing_key() -> PKey<Private> {
    PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap()
}

fn set_certificate_serial(builder: &mut X509Builder, value: u32) {
    let serial = BigNum::from_u32(value).unwrap().to_asn1_integer().unwrap();
    builder.set_serial_number(&serial).unwrap();
}

fn structurally_valid_test_chain() -> (Vec<u8>, Vec<u8>) {
    let root_key = signing_key();
    let mut root_builder = X509Builder::new().unwrap();
    root_builder.set_version(2).unwrap();
    set_certificate_serial(&mut root_builder, 1);
    let root_name = certificate_name("Structural Test Root");
    root_builder.set_subject_name(&root_name).unwrap();
    root_builder.set_issuer_name(&root_name).unwrap();
    root_builder.set_pubkey(&root_key).unwrap();
    root_builder
        .set_not_before(&Asn1Time::from_unix(1_700_000_000).unwrap())
        .unwrap();
    root_builder
        .set_not_after(&Asn1Time::from_unix(1_800_000_000).unwrap())
        .unwrap();
    root_builder
        .append_extension(BasicConstraints::new().critical().ca().build().unwrap())
        .unwrap();
    root_builder
        .append_extension(
            KeyUsage::new()
                .critical()
                .key_cert_sign()
                .crl_sign()
                .build()
                .unwrap(),
        )
        .unwrap();
    let root_ski = SubjectKeyIdentifier::new()
        .build(&root_builder.x509v3_context(None, None))
        .unwrap();
    root_builder.append_extension(root_ski).unwrap();
    root_builder
        .sign(&root_key, MessageDigest::sha256())
        .unwrap();
    let root = root_builder.build();

    let leaf_key = signing_key();
    let mut leaf_builder = X509Builder::new().unwrap();
    leaf_builder.set_version(2).unwrap();
    set_certificate_serial(&mut leaf_builder, 2);
    let leaf_name = certificate_name("Structural Test Leaf");
    leaf_builder.set_subject_name(&leaf_name).unwrap();
    leaf_builder.set_issuer_name(root.subject_name()).unwrap();
    leaf_builder.set_pubkey(&leaf_key).unwrap();
    leaf_builder
        .set_not_before(&Asn1Time::from_unix(1_700_000_000).unwrap())
        .unwrap();
    leaf_builder
        .set_not_after(&Asn1Time::from_unix(1_800_000_000).unwrap())
        .unwrap();
    leaf_builder
        .append_extension(BasicConstraints::new().critical().build().unwrap())
        .unwrap();
    leaf_builder
        .append_extension(
            KeyUsage::new()
                .critical()
                .digital_signature()
                .build()
                .unwrap(),
        )
        .unwrap();
    let leaf_aki = AuthorityKeyIdentifier::new()
        .keyid(true)
        .build(&leaf_builder.x509v3_context(Some(&root), None))
        .unwrap();
    leaf_builder.append_extension(leaf_aki).unwrap();
    leaf_builder
        .sign(&root_key, MessageDigest::sha256())
        .unwrap();

    (
        leaf_builder.build().to_der().unwrap(),
        root.to_der().unwrap(),
    )
}

#[test]
fn api_parses_x509_and_extracts_metadata() {
    let cert = X509CertificateDer {
        der: qwac_certificate_der(),
    };
    let metadata = extract_certificate_metadata_der(&cert)
        .expect("valid repository certificate fixture must parse");

    assert!(metadata.subject.contains("qwac.example.test"));
    assert!(metadata.issuer.contains("qwac.example.test"));
    assert_eq!(metadata.signature_algorithm_oid, "1.2.840.113549.1.1.11");
    assert!(metadata
        .extended_key_usage
        .iter()
        .any(|oid| oid == "1.3.6.1.5.5.7.3.1"));
}

#[test]
fn typed_der_boundary_rejects_empty_oversized_and_excessive_inputs() {
    let empty = X509CertificateDer { der: Vec::new() };
    assert!(matches!(
        extract_certificate_metadata_der(&empty),
        Err(TrustApiError::InvalidInput)
    ));

    let oversized = X509CertificateDer {
        der: vec![0_u8; (1024 * 1024) + 1],
    };
    assert!(matches!(
        extract_certificate_metadata_der(&oversized),
        Err(TrustApiError::InvalidInput)
    ));

    let excessive_chain = X509ChainDer {
        certs: (0..11)
            .map(|_| X509CertificateDer { der: vec![1] })
            .collect(),
    };
    assert!(matches!(
        parse_x509_chain_der(&excessive_chain),
        Err(TrustApiError::InvalidInput)
    ));

    let anchors = TrustAnchorsDer { roots: Vec::new() };
    assert!(matches!(
        validate_certificate_chain_der(&excessive_chain, &anchors, 1_750_000_000),
        Err(TrustApiError::InvalidInput)
    ));
    assert!(matches!(
        validate_trust_anchor_der(&[1], &anchors),
        Err(TrustApiError::InvalidInput)
    ));
}

#[test]
fn typed_der_owner_redacts_and_zeroizes_certificate_bytes() {
    let mut certificate = X509CertificateDer {
        der: vec![1, 2, 3, 4],
    };
    let debug = format!("{certificate:?}");
    assert!(debug.contains("<redacted>"));
    assert!(!debug.contains("1, 2, 3, 4"));

    certificate.zeroize();
    assert!(certificate.der.is_empty());
}

#[test]
fn api_parses_x509_chain_metadata() {
    let chain = X509ChainDer {
        certs: vec![X509CertificateDer {
            der: qwac_certificate_der(),
        }],
    };
    let metadata =
        parse_x509_chain_der(&chain).expect("valid repository certificate fixture must parse");

    assert_eq!(metadata.len(), 1);
    assert!(metadata[0].subject.contains("qwac.example.test"));
}

#[test]
fn structural_chain_screening_never_returns_trusted_without_crypto() {
    let (leaf_der, root_der) = structurally_valid_test_chain();
    let chain = X509ChainDer {
        certs: vec![X509CertificateDer { der: leaf_der }],
    };
    let anchors = TrustAnchorsDer {
        roots: vec![X509CertificateDer { der: root_der }],
    };

    let decision = validate_certificate_chain_der(&chain, &anchors, 1_750_000_000)
        .expect("well-formed candidate chain can be screened structurally");

    // RFC 5280 §6: even exact anchor bytes do not authenticate the child
    // until every child-to-issuer signature has been verified.
    assert!(!decision.accepted);
    assert_eq!(decision.outcome, TrustDecisionOutcome::Indeterminate);
    assert_eq!(
        decision.failures,
        vec![TrustDecisionFailure::SignatureIndeterminate]
    );
    assert!(decision.evidence.trust_anchor.is_none());
    assert!(decision
        .evidence
        .selected_path_certificate_sha256
        .is_empty());
}
