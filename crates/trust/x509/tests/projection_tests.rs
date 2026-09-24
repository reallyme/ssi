// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(clippy::expect_used, clippy::unwrap_used)]

//! Audit-facing X.509 projection and malicious DER tests.

use openssl::{
    asn1::Asn1Time,
    bn::BigNum,
    hash::MessageDigest,
    nid::Nid,
    pkey::PKey,
    rsa::Rsa,
    x509::{extension::BasicConstraints, X509Builder, X509NameBuilder},
};
use reallyme_codec::base64::base64_to_bytes;
use reallyme_trust_x509::{
    certificate_identity_facts, parse_cert_der, parse_cert_pem, parse_chain_pem,
    CertificateExtensionKind, CertificatePolicyId, CertificateVersion, NameAttributeKind,
    PublicKeyProfile, QcStatementId, QcType, SignatureAlgorithm, X509Error, X509ResourceLimit,
    MAX_X509_CERTIFICATE_DER_BYTES, MAX_X509_CERTIFICATE_PEM_BYTES, MAX_X509_CHAIN_PEM_BYTES,
};

const QWAC_CERTIFICATE_DER_BASE64: &str = include_str!("fixtures/qwac_server_auth_cert.der.b64");

#[test]
fn projects_audit_facing_certificate_profile() {
    let der = base64_to_bytes(QWAC_CERTIFICATE_DER_BASE64.trim()).unwrap();
    let certificate = parse_cert_der(&der).unwrap();

    assert_eq!(certificate.profile.version, CertificateVersion::V3);
    assert_eq!(
        certificate.profile.public_key,
        PublicKeyProfile::Rsa { bits: 2048 }
    );
    assert_eq!(
        certificate.profile.signature_algorithm,
        SignatureAlgorithm::RsaPkcs1Sha256
    );
    assert!(certificate.profile.extensions.iter().any(|extension| {
        extension.kind == CertificateExtensionKind::BasicConstraints && extension.critical
    }));
    assert!(certificate.profile.subject.rdns.iter().any(|rdn| {
        rdn.attributes
            .iter()
            .any(|attribute| attribute.kind == NameAttributeKind::CommonName)
    }));
    assert_eq!(
        certificate.profile.certificate_policies,
        [CertificatePolicyId::QevcpWeb]
    );
    assert!(certificate
        .profile
        .qc_statement_ids
        .contains(&QcStatementId::Compliance));
    assert!(certificate
        .profile
        .qc_statement_ids
        .contains(&QcStatementId::Type));
    assert_eq!(certificate.profile.qc_types, [QcType::WebAuthentication]);
}

#[test]
fn rejects_trailing_der_data() {
    let mut der = base64_to_bytes(QWAC_CERTIFICATE_DER_BASE64.trim()).unwrap();
    der.push(0);

    assert_eq!(parse_cert_der(&der), Err(X509Error::InvalidDer));
}

#[test]
fn projects_bounded_trusted_list_identity_facts() {
    let der = base64_to_bytes(QWAC_CERTIFICATE_DER_BASE64.trim()).unwrap();
    let facts = certificate_identity_facts(&der).unwrap();

    assert!(!facts.subject_public_key_info_der.is_empty());
    assert_ne!(facts.derived_subject_key_identifier, [0; 20]);
    assert!(facts.rsa_modulus.is_some());
    assert!(facts.rsa_exponent.is_some());
    assert!(facts.ec_public_key.is_none());
}

#[test]
fn trusted_list_identity_projection_rejects_trailing_and_oversized_der() {
    let mut trailing = base64_to_bytes(QWAC_CERTIFICATE_DER_BASE64.trim()).unwrap();
    trailing.push(0);
    assert_eq!(
        certificate_identity_facts(&trailing).err(),
        Some(X509Error::InvalidDer)
    );

    let oversized = vec![0_u8; MAX_X509_CERTIFICATE_DER_BYTES + 1];
    assert_eq!(
        certificate_identity_facts(&oversized).err(),
        Some(X509Error::ResourceLimitExceeded(
            X509ResourceLimit::CertificateDerTooLarge
        ))
    );
}

#[test]
fn retains_zero_serial_number_for_legacy_anchor_policy_evaluation() {
    let der = certificate_with_extensions(false, true);
    let certificate = parse_cert_der(&der).unwrap();

    assert_eq!(certificate.serial, vec![0]);
}

#[test]
fn rejects_duplicate_extension_oids() {
    let der = certificate_with_extensions(true, false);

    assert_eq!(parse_cert_der(&der), Err(X509Error::DuplicateExtension));
}

#[test]
fn rejects_oversized_certificate_inputs_before_parsing() {
    let oversized_der = vec![0_u8; MAX_X509_CERTIFICATE_DER_BYTES + 1];
    assert_eq!(
        parse_cert_der(&oversized_der),
        Err(X509Error::ResourceLimitExceeded(
            X509ResourceLimit::CertificateDerTooLarge
        ))
    );

    let oversized_pem = vec![b'A'; MAX_X509_CERTIFICATE_PEM_BYTES + 1];
    assert_eq!(
        parse_cert_pem(&oversized_pem),
        Err(X509Error::ResourceLimitExceeded(
            X509ResourceLimit::CertificatePemTooLarge
        ))
    );

    let oversized_bundle = vec![b'A'; MAX_X509_CHAIN_PEM_BYTES + 1];
    assert_eq!(
        parse_chain_pem(&oversized_bundle),
        Err(X509Error::ResourceLimitExceeded(
            X509ResourceLimit::CertificatePemBundleTooLarge
        ))
    );
}

fn certificate_with_extensions(duplicate_basic_constraints: bool, zero_serial: bool) -> Vec<u8> {
    let key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_nid(Nid::COMMONNAME, "projection.test")
        .unwrap();
    let name = name.build();
    let mut builder = X509Builder::new().unwrap();
    builder.set_version(2).unwrap();
    let serial_value = if zero_serial { 0 } else { 1 };
    let serial = BigNum::from_u32(serial_value)
        .unwrap()
        .to_asn1_integer()
        .unwrap();
    builder.set_serial_number(&serial).unwrap();
    builder.set_subject_name(&name).unwrap();
    builder.set_issuer_name(&name).unwrap();
    builder.set_pubkey(&key).unwrap();
    builder
        .set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    builder
        .set_not_after(&Asn1Time::days_from_now(30).unwrap())
        .unwrap();
    builder
        .append_extension(BasicConstraints::new().critical().build().unwrap())
        .unwrap();
    if duplicate_basic_constraints {
        builder
            .append_extension(BasicConstraints::new().critical().build().unwrap())
            .unwrap();
    }
    builder.sign(&key, MessageDigest::sha256()).unwrap();
    builder.build().to_der().unwrap()
}
