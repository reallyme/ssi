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
//! Test coverage for this crate.

use envelopes_x509::model::X509Certificate;
use envelopes_x509::X509Chain;
use reallyme_trust_core::{
    validate_chain_links, ChainLinkPolicy, ChainLinkPolicyViolation, TrustError,
};
use time::OffsetDateTime;

fn mk_cert(
    subject: &str,
    issuer: &str,
    ski: Option<Vec<u8>>,
    aki: Option<Vec<u8>>,
) -> X509Certificate {
    X509Certificate {
        der: vec![],
        subject: subject.to_string(),
        issuer: issuer.to_string(),
        subject_der: subject.as_bytes().to_vec(),
        issuer_der: issuer.as_bytes().to_vec(),
        serial: vec![1],
        not_before: OffsetDateTime::UNIX_EPOCH,
        not_after: OffsetDateTime::UNIX_EPOCH + time::Duration::days(365),
        spki_der: vec![],
        signature_algorithm_oid: "1.2.3".into(),
        basic_constraints: None,
        key_usage: None,
        extended_key_usage: None,
        subject_key_identifier: ski,
        authority_key_identifier: aki,
        san_dns: vec![],
        san_ip: vec![],
        certificate_policies: vec![],
        qc_statements: Default::default(),
        profile: Default::default(),
    }
}

#[test]
fn accepts_matching_aki_ski() {
    let issuer_ski = vec![1, 2, 3];
    let leaf = mk_cert("CN=Leaf", "CN=Issuer", None, Some(issuer_ski.clone()));
    let issuer = mk_cert("CN=Issuer", "CN=Issuer", Some(issuer_ski), None);

    let chain = X509Chain {
        certs: vec![leaf, issuer],
    };
    validate_chain_links(&chain, &ChainLinkPolicy::default()).unwrap();
}

#[test]
fn rejects_mismatched_aki_ski() {
    let leaf = mk_cert("CN=Leaf", "CN=Issuer", None, Some(vec![9, 9, 9]));
    let issuer = mk_cert("CN=Issuer", "CN=Issuer", Some(vec![1, 2, 3]), None);

    let chain = X509Chain {
        certs: vec![leaf, issuer],
    };
    let err = validate_chain_links(&chain, &ChainLinkPolicy::default()).unwrap_err();
    assert!(matches!(err, TrustError::ChainLinkPolicy(_)));
}

#[test]
fn rejects_dn_discontinuity() {
    let ski = vec![1, 2, 3];
    let leaf = mk_cert("CN=Leaf", "CN=WrongIssuer", None, Some(ski.clone()));
    let issuer = mk_cert("CN=Issuer", "CN=Issuer", Some(ski), None);

    let chain = X509Chain {
        certs: vec![leaf, issuer],
    };
    let err = validate_chain_links(&chain, &ChainLinkPolicy::default()).unwrap_err();
    assert!(matches!(err, TrustError::ChainLinkPolicy(_)));
}

#[test]
fn allows_missing_aki_ski_if_configured() {
    let leaf = mk_cert("CN=Leaf", "CN=Issuer", None, None);
    let issuer = mk_cert("CN=Issuer", "CN=Issuer", None, None);

    let chain = X509Chain {
        certs: vec![leaf, issuer],
    };

    let policy = ChainLinkPolicy {
        require_dn_continuity: true,
        require_aki_ski_when_present: false,
    };

    validate_chain_links(&chain, &policy).unwrap();
}

#[test]
fn rejects_names_whose_display_strings_collide_but_der_differs() {
    // `CN=Issuer` encoded as PrintableString and as UTF8String renders to the
    // same display string. Chaining compares the exact DER Name encodings, so
    // the rendered collision must not link the certificates.
    let printable_name = [
        0x30, 0x11, 0x31, 0x0f, 0x30, 0x0d, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x06, b'I', b's',
        b's', b'u', b'e', b'r',
    ];
    let utf8_name = [
        0x30, 0x11, 0x31, 0x0f, 0x30, 0x0d, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x06, b'I', b's',
        b's', b'u', b'e', b'r',
    ];
    let mut leaf = mk_cert("CN=Leaf", "CN=Issuer", None, None);
    leaf.issuer_der = utf8_name.to_vec();
    let mut issuer = mk_cert("CN=Issuer", "CN=Issuer", None, None);
    issuer.subject_der = printable_name.to_vec();
    issuer.issuer_der = printable_name.to_vec();
    assert_eq!(leaf.issuer, issuer.subject);

    let chain = X509Chain {
        certs: vec![leaf, issuer],
    };
    let policy = ChainLinkPolicy {
        require_dn_continuity: true,
        require_aki_ski_when_present: false,
    };
    let err = validate_chain_links(&chain, &policy).unwrap_err();
    assert_eq!(
        err,
        TrustError::ChainLinkPolicy(ChainLinkPolicyViolation::IssuerDistinguishedNameMismatch)
    );
}
