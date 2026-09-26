// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(missing_docs, clippy::unwrap_used)]
//! Test coverage for this crate.

use reallyme_trust_x509::{
    eu_policy, screen_chain_policy_only_no_path_validation, validate_tsl_trust_service_for_leaf,
    BasicConstraints, CertificatePolicyId, CertificateProfile, EuPreset, ExtendedKeyUsagePurpose,
    KeyUsage, ObjectIdentifier, PublicKeyProfile, QcStatementId, QcStatements, QcType,
    SignatureAlgorithm, TslCertificateBinding, TslServiceStatus, TslServiceType, TslTrustService,
    TslValidationPolicy, X509Certificate, X509Chain, X509Error, X509PolicyFailure,
};
use serde_json::Value;
use time::OffsetDateTime;

const X509_TRUST_POLICY_VECTORS: &str = include_str!("../../../../vectors/x509-trust-policy.json");

#[test]
fn x509_trust_policy_vectors_validate_or_fail_closed() {
    let suite: Value = serde_json::from_str(X509_TRUST_POLICY_VECTORS).unwrap();
    assert_eq!(
        suite["schema"].as_str().unwrap(),
        "reallyme.identity.conformance.x509_trust_policy.v1"
    );

    for case in suite["certificate_policy_cases"].as_array().unwrap() {
        let chain = chain_from_vector(&case["chain"]);
        let preset = preset_from_str(case["preset"].as_str().unwrap()).unwrap();
        let policy = eu_policy(preset);
        let validation_time = unix_time(case["validation_time_unix"].as_i64().unwrap());
        let actual = screen_chain_policy_only_no_path_validation(&chain, validation_time, &policy);
        assert_result(actual, case["expected"]["result"].as_str().unwrap());
    }

    for case in suite["tsl_policy_cases"].as_array().unwrap() {
        let leaf = tsl_leaf_from_vector(&case["leaf"]);
        let service = service_from_vector(&case["service"]);
        let policy = tsl_policy_from_vector(&case["policy"]);
        let actual = validate_tsl_trust_service_for_leaf(&service, &leaf, &policy);
        assert_result(actual, case["expected"]["result"].as_str().unwrap());
    }
}

fn chain_from_vector(value: &Value) -> X509Chain {
    let certs = value["certs"]
        .as_array()
        .unwrap()
        .iter()
        .map(cert_from_vector)
        .collect();
    X509Chain { certs }
}

fn cert_from_vector(value: &Value) -> X509Certificate {
    let is_ca = value["basic_constraints"]["ca"].as_bool().unwrap_or(false);
    let extended_key_usage = value["extended_key_usage"]
        .as_array()
        .map(|values| values.iter().map(eku_from_value).collect())
        .unwrap_or_default();
    let certificate_policies = value["certificate_policies"]
        .as_array()
        .unwrap()
        .iter()
        .map(policy_from_value)
        .collect();
    let qc_statement_ids = value["qc_statement_ids"]
        .as_array()
        .unwrap()
        .iter()
        .map(qc_statement_from_value)
        .collect();
    let qc_types = value["qc_types"]
        .as_array()
        .unwrap()
        .iter()
        .map(qc_type_from_value)
        .collect();
    let mut profile = CertificateProfile::default();
    profile.public_key = PublicKeyProfile::Rsa { bits: 2048 };
    profile.signature_algorithm = SignatureAlgorithm::RsaPkcs1Sha256;
    profile.extended_key_usage = extended_key_usage;
    profile.certificate_policies = certificate_policies;
    profile.qc_statement_ids = qc_statement_ids;
    profile.qc_types = qc_types;
    X509Certificate {
        der: Vec::new(),
        subject: value["subject"].as_str().unwrap().to_owned(),
        issuer: value["issuer"].as_str().unwrap().to_owned(),
        subject_der: value["subject"].as_str().unwrap().as_bytes().to_vec(),
        issuer_der: value["issuer"].as_str().unwrap().as_bytes().to_vec(),
        serial: hex_to_bytes(value["serial_hex"].as_str().unwrap()),
        not_before: unix_time(value["not_before_unix"].as_i64().unwrap()),
        not_after: unix_time(value["not_after_unix"].as_i64().unwrap()),
        spki_der: Vec::new(),
        signature_algorithm_oid: "1.2.840.10045.4.3.2".to_owned(),
        basic_constraints: basic_constraints_from_vector(&value["basic_constraints"]),
        key_usage: key_usage_from_vector(&value["key_usage"]),
        extended_key_usage: value["extended_key_usage"]
            .as_array()
            .map(|values| string_array(values)),
        subject_key_identifier: None,
        authority_key_identifier: None,
        san_dns: if is_ca {
            Vec::new()
        } else {
            vec!["vector.example".to_owned()]
        },
        san_ip: Vec::new(),
        certificate_policies: string_array(value["certificate_policies"].as_array().unwrap()),
        qc_statements: QcStatements {
            statement_ids: string_array(value["qc_statement_ids"].as_array().unwrap()),
            qc_types: string_array(value["qc_types"].as_array().unwrap()),
        },
        profile,
    }
}

fn oid_from_value(value: &Value) -> ObjectIdentifier {
    ObjectIdentifier::parse(value.as_str().unwrap()).unwrap()
}

fn eku_from_value(value: &Value) -> ExtendedKeyUsagePurpose {
    match value.as_str().unwrap() {
        "1.3.6.1.5.5.7.3.1" => ExtendedKeyUsagePurpose::ServerAuthentication,
        "1.3.6.1.5.5.7.3.2" => ExtendedKeyUsagePurpose::ClientAuthentication,
        _ => ExtendedKeyUsagePurpose::Other(oid_from_value(value)),
    }
}

fn policy_from_value(value: &Value) -> CertificatePolicyId {
    match value.as_str().unwrap() {
        "0.4.0.194112.1.0" => CertificatePolicyId::QcpNaturalPerson,
        "0.4.0.194112.1.1" => CertificatePolicyId::QcpLegalPerson,
        "0.4.0.194112.1.2" => CertificatePolicyId::QcpNaturalPersonQscd,
        "0.4.0.194112.1.3" => CertificatePolicyId::QcpLegalPersonQscd,
        "0.4.0.194112.1.4" => CertificatePolicyId::QevcpWeb,
        "0.4.0.194112.1.5" => CertificatePolicyId::QncpWeb,
        "0.4.0.194112.1.6" => CertificatePolicyId::QncpWebGeneric,
        _ => CertificatePolicyId::Other(oid_from_value(value)),
    }
}

fn qc_statement_from_value(value: &Value) -> QcStatementId {
    match value.as_str().unwrap() {
        "0.4.0.1862.1.1" => QcStatementId::Compliance,
        "0.4.0.1862.1.6" => QcStatementId::Type,
        _ => QcStatementId::Other(oid_from_value(value)),
    }
}

fn qc_type_from_value(value: &Value) -> QcType {
    match value.as_str().unwrap() {
        "0.4.0.1862.1.6.1" => QcType::ElectronicSignature,
        "0.4.0.1862.1.6.2" => QcType::ElectronicSeal,
        "0.4.0.1862.1.6.3" => QcType::WebAuthentication,
        _ => QcType::Other(oid_from_value(value)),
    }
}

fn basic_constraints_from_vector(value: &Value) -> Option<BasicConstraints> {
    if value.is_null() {
        return None;
    }
    let path_len_constraint = value["path_len_constraint"]
        .as_u64()
        .map(|raw| u32::try_from(raw).unwrap());
    Some(BasicConstraints {
        ca: value["ca"].as_bool().unwrap(),
        path_len_constraint,
    })
}

fn key_usage_from_vector(value: &Value) -> Option<KeyUsage> {
    if value.is_null() {
        return None;
    }
    Some(KeyUsage {
        digital_signature: value["digital_signature"].as_bool().unwrap(),
        content_commitment: false,
        key_cert_sign: value["key_cert_sign"].as_bool().unwrap(),
        crl_sign: value["crl_sign"].as_bool().unwrap(),
        key_encipherment: value["key_encipherment"].as_bool().unwrap(),
        data_encipherment: false,
        key_agreement: value["key_agreement"].as_bool().unwrap(),
        encipher_only: false,
        decipher_only: false,
    })
}

fn tsl_leaf_from_vector(value: &Value) -> X509Certificate {
    X509Certificate {
        der: hex_to_bytes(value["der_hex"].as_str().unwrap()),
        subject: "CN=leaf".to_owned(),
        issuer: "CN=issuer".to_owned(),
        subject_der: b"CN=leaf".to_vec(),
        issuer_der: b"CN=issuer".to_vec(),
        serial: vec![1],
        not_before: unix_time(1_767_225_600),
        not_after: unix_time(1_769_904_000),
        spki_der: hex_to_bytes(value["spki_der_hex"].as_str().unwrap()),
        signature_algorithm_oid: "1.2.840.10045.4.3.2".to_owned(),
        basic_constraints: None,
        key_usage: None,
        extended_key_usage: None,
        subject_key_identifier: value["subject_key_identifier_hex"]
            .as_str()
            .map(hex_to_bytes),
        authority_key_identifier: None,
        san_dns: Vec::new(),
        san_ip: Vec::new(),
        certificate_policies: Vec::new(),
        qc_statements: QcStatements::default(),
        profile: Default::default(),
    }
}

fn service_from_vector(value: &Value) -> TslTrustService {
    let certificate_bindings = value["certificate_bindings"]
        .as_array()
        .unwrap()
        .iter()
        .map(binding_from_vector)
        .collect();
    TslTrustService {
        territory: value["territory"].as_str().unwrap().to_owned(),
        provider_name: "Vector Provider".to_owned(),
        service_name: "Vector Service".to_owned(),
        service_type: service_type_from_str(value["service_type"].as_str().unwrap()).unwrap(),
        status: service_status_from_str(value["status"].as_str().unwrap()).unwrap(),
        status_start_time: unix_time(value["status_start_time_unix"].as_i64().unwrap()),
        certificate_bindings,
    }
}

fn binding_from_vector(value: &Value) -> TslCertificateBinding {
    TslCertificateBinding {
        certificate_der: value["certificate_der_hex"].as_str().map(hex_to_bytes),
        subject_key_identifier: value["subject_key_identifier_hex"]
            .as_str()
            .map(hex_to_bytes),
    }
}

fn tsl_policy_from_vector(value: &Value) -> TslValidationPolicy {
    TslValidationPolicy {
        required_territory: value["required_territory"].as_str().map(str::to_owned),
        required_service_type: value["required_service_type"]
            .as_str()
            .map(service_type_from_str)
            .map(Option::unwrap),
        require_granted_status: value["require_granted_status"].as_bool().unwrap(),
        require_leaf_binding: value["require_leaf_binding"].as_bool().unwrap(),
        validation_time: value["validation_time_unix"].as_i64().map(unix_time),
        max_status_age_seconds: value["max_status_age_seconds"].as_u64(),
    }
}

fn preset_from_str(value: &str) -> Option<EuPreset> {
    match value {
        "Qwac" => Some(EuPreset::Qwac),
        "Qsealc" => Some(EuPreset::Qsealc),
        "Qsigc" => Some(EuPreset::Qsigc),
        _ => None,
    }
}

fn service_type_from_str(value: &str) -> Option<TslServiceType> {
    match value {
        "CaQc" => Some(TslServiceType::CaQc),
        "OcspQc" => Some(TslServiceType::OcspQc),
        "Other" => Some(TslServiceType::Other),
        _ => None,
    }
}

fn service_status_from_str(value: &str) -> Option<TslServiceStatus> {
    match value {
        "Granted" => Some(TslServiceStatus::Granted),
        "Withdrawn" => Some(TslServiceStatus::Withdrawn),
        "Deprecated" => Some(TslServiceStatus::Deprecated),
        "Other" => Some(TslServiceStatus::Other),
        _ => None,
    }
}

fn assert_result(actual: Result<(), X509Error>, expected: &str) {
    if expected == "ok" {
        actual.unwrap();
        return;
    }
    assert_eq!(actual.unwrap_err(), expected_error(expected).unwrap());
}

fn expected_error(value: &str) -> Option<X509Error> {
    match value {
        "LeafQcTypeMismatch" => Some(X509Error::PolicyFailed(
            X509PolicyFailure::LeafQcTypeMismatch,
        )),
        "LeafMissingRequiredQcStatement" => Some(X509Error::PolicyFailed(
            X509PolicyFailure::LeafMissingRequiredQcStatement,
        )),
        "TslTerritoryMismatch" => Some(X509Error::PolicyFailed(
            X509PolicyFailure::TslTerritoryMismatch,
        )),
        "TslStatusTooOld" => Some(X509Error::PolicyFailed(X509PolicyFailure::TslStatusTooOld)),
        "TslCertificateBindingMismatch" => Some(X509Error::PolicyFailed(
            X509PolicyFailure::TslCertificateBindingMismatch,
        )),
        _ => None,
    }
}

fn string_array(values: &[Value]) -> Vec<String> {
    values
        .iter()
        .map(|value| value.as_str().unwrap().to_owned())
        .collect()
}

fn unix_time(value: i64) -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(value).unwrap()
}

fn hex_to_bytes(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0, "hex strings must have even length");
    let mut out = Vec::with_capacity(value.len() / 2);
    for chunk in value.as_bytes().chunks(2) {
        let hex = core::str::from_utf8(chunk).unwrap();
        out.push(u8::from_str_radix(hex, 16).unwrap());
    }
    out
}
