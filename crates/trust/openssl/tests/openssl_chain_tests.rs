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
//! Tests for OpenSSL-backed trust chain verification.

use identity_trust_openssl::OpenSslSignatureVerifier;
use reallyme_trust_core::SignatureVerifier;

use envelopes_x509::{parse_cert_der, X509Chain};

use openssl::{
    asn1::{Asn1Time, Asn1Type},
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
    // fast for tests: RSA 2048
    let rsa = Rsa::generate(2048).unwrap();
    PKey::from_rsa(rsa).unwrap()
}

fn build_root(cn: &str) -> (X509, PKey<Private>) {
    let now = OffsetDateTime::now_utc().unix_timestamp();
    build_root_valid_during(cn, now - 60, now + 315_360_000)
}

fn build_root_valid_during(cn: &str, not_before: i64, not_after: i64) -> (X509, PKey<Private>) {
    let key = gen_key();
    let mut b = X509Builder::new().unwrap();

    b.set_version(2).unwrap();
    set_serial(&mut b, 1);

    let name = make_name(cn);
    b.set_subject_name(&name).unwrap();
    b.set_issuer_name(&name).unwrap();

    b.set_pubkey(&key).unwrap();
    b.set_not_before(&Asn1Time::from_unix(not_before).unwrap())
        .unwrap();
    b.set_not_after(&Asn1Time::from_unix(not_after).unwrap())
        .unwrap();

    // v3_ca
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
    let now = OffsetDateTime::now_utc().unix_timestamp();
    build_leaf_valid_during(cn, issuer, issuer_key, serial, now - 60, now + 34_300_800)
}

fn build_leaf_valid_during(
    cn: &str,
    issuer: &X509,
    issuer_key: &PKey<Private>,
    serial: u32,
    not_before: i64,
    not_after: i64,
) -> X509 {
    let key = gen_key();
    let mut b = X509Builder::new().unwrap();

    b.set_version(2).unwrap();
    set_serial(&mut b, serial);

    let subject = make_name(cn);
    b.set_subject_name(&subject).unwrap();
    b.set_issuer_name(issuer.subject_name()).unwrap();

    b.set_pubkey(&key).unwrap();
    b.set_not_before(&Asn1Time::from_unix(not_before).unwrap())
        .unwrap();
    b.set_not_after(&Asn1Time::from_unix(not_after).unwrap())
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

    let root_der = root.to_der().unwrap();
    let leaf_der = leaf.to_der().unwrap();

    let root_env = parse_cert_der(&root_der).unwrap();
    let leaf_env = parse_cert_der(&leaf_der).unwrap();

    let chain = X509Chain {
        certs: vec![leaf_env, root_env],
    };

    let verifier = OpenSslSignatureVerifier::new();
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

    let verifier = OpenSslSignatureVerifier::new();
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

    // Chain uses wrong trust anchor
    let chain = X509Chain {
        certs: vec![leaf_env, wrong_root_env],
    };

    let verifier = OpenSslSignatureVerifier::new();
    let err = verifier
        .verify_chain(&chain, OffsetDateTime::now_utc())
        .unwrap_err();

    assert!(matches!(
        err,
        reallyme_trust_core::SignatureVerifyError::InvalidSignature
    ));
}

#[test]
fn rejects_wrong_root_with_same_subject_dn() {
    let (signing_root, signing_root_key) = build_root("Reused Root Name");
    let leaf = build_leaf("Reused Root Name", &signing_root, &signing_root_key, 106);
    let (configured_root, _) = build_root("Reused Root Name");
    let chain = X509Chain {
        certs: vec![
            parse_cert_der(&leaf.to_der().unwrap()).unwrap(),
            parse_cert_der(&configured_root.to_der().unwrap()).unwrap(),
        ],
    };

    // RFC 5280 §6 requires signature validation against the exact configured
    // anchor. A matching Subject DN is only a name relation, never proof that
    // the child was signed by that anchor (CVE-2026-75522).
    let error = OpenSslSignatureVerifier::new()
        .verify_chain(&chain, OffsetDateTime::now_utc())
        .expect_err("same-subject forged path must fail cryptographic validation");

    assert!(matches!(
        error,
        reallyme_trust_core::SignatureVerifyError::InvalidSignature
    ));
}

fn chain_valid_during(not_before: i64, not_after: i64) -> X509Chain {
    let (root, root_key) = build_root_valid_during("CN=TimeRoot", not_before, not_after);
    let leaf = build_leaf_valid_during("CN=TimeLeaf", &root, &root_key, 103, not_before, not_after);

    X509Chain {
        certs: vec![
            parse_cert_der(&leaf.to_der().unwrap()).unwrap(),
            parse_cert_der(&root.to_der().unwrap()).unwrap(),
        ],
    }
}

#[test]
fn rejects_certificate_not_yet_valid_at_supplied_time() {
    let not_before = 1_700_000_000;
    let not_after = 1_800_000_000;
    let chain = chain_valid_during(not_before, not_after);
    let evaluation_time = OffsetDateTime::from_unix_timestamp(not_before - 86_400).unwrap();

    let error = OpenSslSignatureVerifier::new()
        .verify_chain(&chain, evaluation_time)
        .unwrap_err();

    assert!(matches!(
        error,
        reallyme_trust_core::SignatureVerifyError::InvalidSignature
    ));
}

#[test]
fn rejects_certificate_expired_at_supplied_time() {
    let not_before = 1_700_000_000;
    let not_after = 1_800_000_000;
    let chain = chain_valid_during(not_before, not_after);
    let evaluation_time = OffsetDateTime::from_unix_timestamp(not_after + 86_400).unwrap();

    let error = OpenSslSignatureVerifier::new()
        .verify_chain(&chain, evaluation_time)
        .unwrap_err();

    assert!(matches!(
        error,
        reallyme_trust_core::SignatureVerifyError::InvalidSignature
    ));
}

#[test]
fn verifies_historical_chain_at_supplied_historical_time() {
    let not_before = 1_577_836_800;
    let not_after = 1_609_459_200;
    let chain = chain_valid_during(not_before, not_after);
    let evaluation_time = OffsetDateTime::from_unix_timestamp(1_593_561_600).unwrap();

    OpenSslSignatureVerifier::new()
        .verify_chain(&chain, evaluation_time)
        .unwrap();
}

#[test]
fn rejects_issuer_name_that_only_matches_by_display_string() {
    let (root, root_key) = build_root("Colliding Root");
    // Encode the leaf's issuer CN with the other string type than the root's
    // subject: the rendered display strings collide while the DER differs.
    let root_der = root.to_der().unwrap();
    let common_name = b"Colliding Root";
    let common_name_offset = root_der
        .windows(common_name.len())
        .position(|window| window == common_name)
        .unwrap();
    let alternate_type = if root_der[common_name_offset - 2] == 0x0c {
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
    let mut b = X509Builder::new().unwrap();
    b.set_version(2).unwrap();
    set_serial(&mut b, 107);
    b.set_subject_name(&make_name("Leaf")).unwrap();
    b.set_issuer_name(&alternate_name).unwrap();
    b.set_pubkey(&key).unwrap();
    let now = OffsetDateTime::now_utc().unix_timestamp();
    b.set_not_before(&Asn1Time::from_unix(now - 60).unwrap())
        .unwrap();
    b.set_not_after(&Asn1Time::from_unix(now + 86_400).unwrap())
        .unwrap();
    b.sign(&root_key, MessageDigest::sha256()).unwrap();
    let leaf = b.build();

    let chain = X509Chain {
        certs: vec![
            parse_cert_der(&leaf.to_der().unwrap()).unwrap(),
            parse_cert_der(&root_der).unwrap(),
        ],
    };
    assert_eq!(chain.certs[0].issuer, chain.certs[1].subject);
    assert_ne!(chain.certs[0].issuer_der, chain.certs[1].subject_der);

    let error = OpenSslSignatureVerifier::new()
        .verify_chain(&chain, OffsetDateTime::now_utc())
        .expect_err("display-string-only issuer match must not chain");

    assert!(matches!(
        error,
        reallyme_trust_core::SignatureVerifyError::InvalidSignature
    ));
}
