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
use time::{Date, Month, OffsetDateTime, PrimitiveDateTime, Time};

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
        serial: vec![1],
        not_before: instant(1),
        not_after: instant(31),
        spki_der: vec![0x30, 0x02, 0x02],
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
        subject_key_identifier: Some(vec![9, 9, 9]),
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
            subject_key_identifier: Some(vec![9, 9, 9]),
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
