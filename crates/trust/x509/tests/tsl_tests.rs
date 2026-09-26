// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(missing_docs, clippy::unwrap_used)]
//! Test coverage for this crate.

use reallyme_trust_x509::{
    validate_tsl_trust_service_for_leaf, BasicConstraints, KeyUsage, QcStatements,
    TslCertificateBinding, TslServiceStatus, TslServiceType, TslTrustService, TslValidationPolicy,
    X509Certificate, X509Error, X509PolicyFailure,
};
use sha1::{Digest, Sha1};
use time::{Date, Month, OffsetDateTime, PrimitiveDateTime, Time};

/// RFC 8410 Ed25519 SubjectPublicKeyInfo prefix; the 32 key octets follow.
const ED25519_SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];
const ED25519_PUBLIC_KEY: [u8; 32] = [0x5a; 32];

fn leaf_spki_der() -> Vec<u8> {
    let mut spki = ED25519_SPKI_PREFIX.to_vec();
    spki.extend_from_slice(&ED25519_PUBLIC_KEY);
    spki
}

/// RFC 5280 Section 4.2.1.2 method 1 over the subjectPublicKey bits.
fn method_one_key_identifier() -> Vec<u8> {
    Sha1::digest(ED25519_PUBLIC_KEY).to_vec()
}

/// RFC 7093 Section 2 method 1: leftmost 160 bits of SHA-256.
fn rfc7093_sha256_key_identifier() -> Vec<u8> {
    reallyme_crypto::sha2::digest(&ED25519_PUBLIC_KEY).as_bytes()[..20].to_vec()
}

fn instant(day: u8) -> OffsetDateTime {
    PrimitiveDateTime::new(
        Date::from_calendar_date(2026, Month::January, day).unwrap(),
        Time::MIDNIGHT,
    )
    .assume_utc()
}

fn leaf() -> X509Certificate {
    X509Certificate {
        der: vec![0x30, 0x03, 0x01],
        subject: "CN=leaf".to_owned(),
        issuer: "CN=issuer".to_owned(),
        subject_der: b"CN=leaf".to_vec(),
        issuer_der: b"CN=issuer".to_vec(),
        serial: vec![1],
        not_before: instant(1),
        not_after: instant(31),
        spki_der: leaf_spki_der(),
        signature_algorithm_oid: "1.3.101.112".to_owned(),
        basic_constraints: Some(BasicConstraints {
            ca: false,
            path_len_constraint: None,
        }),
        key_usage: Some(KeyUsage {
            digital_signature: true,
            content_commitment: false,
            key_cert_sign: false,
            crl_sign: false,
            key_encipherment: false,
            data_encipherment: false,
            key_agreement: false,
            encipher_only: false,
            decipher_only: false,
        }),
        extended_key_usage: None,
        subject_key_identifier: Some(method_one_key_identifier()),
        authority_key_identifier: None,
        san_dns: Vec::new(),
        san_ip: Vec::new(),
        certificate_policies: Vec::new(),
        qc_statements: QcStatements::default(),
        profile: Default::default(),
    }
}

fn service() -> TslTrustService {
    TslTrustService {
        territory: "DE".to_owned(),
        provider_name: "Qualified Provider".to_owned(),
        service_name: "Qualified CA".to_owned(),
        service_type: TslServiceType::CaQc,
        status: TslServiceStatus::Granted,
        status_start_time: instant(1),
        certificate_bindings: vec![TslCertificateBinding {
            certificate_der: None,
            subject_key_identifier: Some(method_one_key_identifier()),
        }],
    }
}

#[test]
fn tsl_policy_accepts_granted_bound_service() {
    let policy = TslValidationPolicy::eu_qualified_ca("DE", instant(2));

    validate_tsl_trust_service_for_leaf(&service(), &leaf(), &policy).unwrap();
}

#[test]
fn tsl_policy_rejects_non_granted_service() {
    let mut service = service();
    service.status = TslServiceStatus::Withdrawn;
    let policy = TslValidationPolicy::eu_qualified_ca("DE", instant(2));

    let err = validate_tsl_trust_service_for_leaf(&service, &leaf(), &policy).unwrap_err();

    assert_eq!(
        err,
        X509Error::PolicyFailed(X509PolicyFailure::TslStatusNotGranted)
    );
}

#[test]
fn tsl_policy_rejects_wrong_service_type() {
    let mut service = service();
    service.service_type = TslServiceType::OcspQc;
    let policy = TslValidationPolicy::eu_qualified_ca("DE", instant(2));

    let err = validate_tsl_trust_service_for_leaf(&service, &leaf(), &policy).unwrap_err();

    assert_eq!(
        err,
        X509Error::PolicyFailed(X509PolicyFailure::TslServiceTypeMismatch)
    );
}

#[test]
fn tsl_policy_rejects_wrong_territory() {
    let policy = TslValidationPolicy::eu_qualified_ca("FR", instant(2));

    let err = validate_tsl_trust_service_for_leaf(&service(), &leaf(), &policy).unwrap_err();

    assert_eq!(
        err,
        X509Error::PolicyFailed(X509PolicyFailure::TslTerritoryMismatch)
    );
}

#[test]
fn tsl_policy_rejects_service_not_yet_effective() {
    let policy = TslValidationPolicy::eu_qualified_ca("DE", instant(1));
    let mut service = service();
    service.status_start_time = instant(2);

    let err = validate_tsl_trust_service_for_leaf(&service, &leaf(), &policy).unwrap_err();

    assert_eq!(
        err,
        X509Error::PolicyFailed(X509PolicyFailure::TslStatusNotEffective)
    );
}

#[test]
fn tsl_policy_rejects_stale_service_status() {
    let mut policy = TslValidationPolicy::eu_qualified_ca("DE", instant(10));
    policy.max_status_age_seconds = Some(86_400);

    let err = validate_tsl_trust_service_for_leaf(&service(), &leaf(), &policy).unwrap_err();

    assert_eq!(
        err,
        X509Error::PolicyFailed(X509PolicyFailure::TslStatusTooOld)
    );
}

#[test]
fn tsl_policy_accepts_der_certificate_binding() {
    let leaf = leaf();
    let mut service = service();
    service.certificate_bindings = vec![TslCertificateBinding {
        certificate_der: Some(leaf.der.clone()),
        subject_key_identifier: None,
    }];
    let policy = TslValidationPolicy::eu_qualified_ca("DE", instant(2));

    validate_tsl_trust_service_for_leaf(&service, &leaf, &policy).unwrap();
}

#[test]
fn tsl_policy_rejects_missing_leaf_binding() {
    let mut service = service();
    service.certificate_bindings.clear();
    let policy = TslValidationPolicy::eu_qualified_ca("DE", instant(2));

    let err = validate_tsl_trust_service_for_leaf(&service, &leaf(), &policy).unwrap_err();

    assert_eq!(
        err,
        X509Error::PolicyFailed(X509PolicyFailure::TslCertificateBindingMissing)
    );
}

#[test]
fn tsl_policy_rejects_leaf_binding_mismatch() {
    let mut service = service();
    service.certificate_bindings[0].subject_key_identifier = Some(vec![7, 7, 7]);
    let policy = TslValidationPolicy::eu_qualified_ca("DE", instant(2));

    let err = validate_tsl_trust_service_for_leaf(&service, &leaf(), &policy).unwrap_err();

    assert_eq!(
        err,
        X509Error::PolicyFailed(X509PolicyFailure::TslCertificateBindingMismatch)
    );
}

#[test]
fn tsl_policy_rejects_binding_to_forged_subject_key_identifier_extension() {
    // The leaf's SubjectKeyIdentifier extension claims an identifier that is
    // not derived from its public key. A binding naming that claimed value
    // must not match: only identifiers computed from the SPKI count.
    let forged_identifier = vec![0x09; 20];
    let mut leaf = leaf();
    leaf.subject_key_identifier = Some(forged_identifier.clone());
    let mut service = service();
    service.certificate_bindings[0].subject_key_identifier = Some(forged_identifier);
    let policy = TslValidationPolicy::eu_qualified_ca("DE", instant(2));

    let err = validate_tsl_trust_service_for_leaf(&service, &leaf, &policy).unwrap_err();

    assert_eq!(
        err,
        X509Error::PolicyFailed(X509PolicyFailure::TslCertificateBindingMismatch)
    );
}

#[test]
fn tsl_policy_matches_computed_identifier_regardless_of_extension() {
    let mut leaf = leaf();
    leaf.subject_key_identifier = None;
    let policy = TslValidationPolicy::eu_qualified_ca("DE", instant(2));

    validate_tsl_trust_service_for_leaf(&service(), &leaf, &policy).unwrap();

    let mut rfc7093_service = service();
    rfc7093_service.certificate_bindings[0].subject_key_identifier =
        Some(rfc7093_sha256_key_identifier());
    validate_tsl_trust_service_for_leaf(&rfc7093_service, &leaf, &policy).unwrap();
}

#[test]
fn key_identifier_matching_uses_only_spki_derived_values() {
    let leaf = leaf();
    let method_one = method_one_key_identifier();
    let sha256 = reallyme_crypto::sha2::digest(&ED25519_PUBLIC_KEY);
    let sha384 = reallyme_crypto::sha2::digest_sha2_384(&ED25519_PUBLIC_KEY);
    let sha512 = reallyme_crypto::sha2::digest_sha2_512(&ED25519_PUBLIC_KEY);

    assert!(leaf.matches_key_identifier(&method_one));
    assert!(leaf.matches_key_identifier(&sha256.as_bytes()[..20]));
    assert!(leaf.matches_key_identifier(&sha384.as_bytes()[..20]));
    assert!(leaf.matches_key_identifier(&sha512.as_bytes()[..20]));

    // Truncated, extended, empty, and full-length SHA-2 values never match.
    assert!(!leaf.matches_key_identifier(&method_one[..19]));
    let mut extended = method_one.clone();
    extended.push(0);
    assert!(!leaf.matches_key_identifier(&extended));
    assert!(!leaf.matches_key_identifier(&[]));
    assert!(!leaf.matches_key_identifier(sha256.as_bytes()));

    // The SubjectKeyIdentifier extension value is never consulted.
    let mut forged = leaf.clone();
    forged.subject_key_identifier = Some(vec![0x09; 20]);
    assert!(!forged.matches_key_identifier(&[0x09; 20]));

    // Malformed SPKI material never matches.
    let mut malformed = leaf.clone();
    malformed.spki_der = vec![0x30, 0x02, 0x02];
    assert!(!malformed.matches_key_identifier(&method_one));
    let mut trailing = leaf.clone();
    trailing.spki_der.push(0x00);
    assert!(!trailing.matches_key_identifier(&method_one));
    let mut empty = leaf;
    empty.spki_der.clear();
    assert!(!empty.matches_key_identifier(&method_one));
}
