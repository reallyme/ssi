// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(missing_docs, clippy::unwrap_used)]
//! Test coverage for this crate.

use reallyme_credential_audit::{
    validate_qeaa_compliance, IdentityProofing, IdentityProofingLevel, IssuerCredential,
    IssuerCredentialKind, KeyManagement, KeyProtection, QeaaCompliance, QeaaComplianceError,
    QeaaField, QeaaInvalidReason, QeaaPolicies, QtspInfo, QtspRole, RevocationPolicy, StatusMethod,
    MAX_CERT_CHAIN_LEN, MAX_CERT_CHAIN_TOTAL_DER_BYTES, MAX_CERT_DER_BYTES,
};

fn sample_qeaa() -> QeaaCompliance {
    QeaaCompliance {
        qtsp: QtspInfo {
            tsp_name: "Test QTSP".to_owned(),
            tsp_id: "EU:QTSP:123".to_owned(),
            tsp_role: QtspRole::QeaaProvider,
        },
        policies: QeaaPolicies {
            policy_id: "eu-qeaa-policy-v1".to_owned(),
            standards: vec!["ETSI EN 319 411-2".to_owned(), "ETSI TS 119 461".to_owned()],
        },
        issuer_credential: IssuerCredential {
            kind: IssuerCredentialKind::X509,
            cert_fingerprint_sha256: [7; 32],
            cert_chain_der: vec![vec![0x30, 0x03, 0x01]],
            trusted_list_ref: "EU-TSL:example".to_owned(),
            policy_oids: vec!["0.4.0.194112.1.3".to_owned()],
            qcstatements_oids: vec!["0.4.0.1862.1.1".to_owned()],
        },
        key_management: KeyManagement {
            signing_key_id: "issuer-signing-key-1".to_owned(),
            protection: KeyProtection::Qscd,
        },
        identity_proofing: IdentityProofing {
            standard: "ETSI TS 119 461".to_owned(),
            loip: IdentityProofingLevel::High,
            evidence_ref: "urn:reallyme:evidence:proofing:1".to_owned(),
            evidence_hash: [9; 32],
        },
        audit: reallyme_credential_audit::AuditInfo {
            audit_standard: "ETSI EN 319 403-1".to_owned(),
            audit_report_ref: "urn:reallyme:audit:report:1".to_owned(),
            audit_report_hash: [3; 32],
            period_from_unix: 1_700_000_000,
            period_to_unix: 1_800_000_000,
        },
        revocation: RevocationPolicy {
            status_method: StatusMethod::StatusList,
            signing_key_id: "status-signing-key-1".to_owned(),
            max_status_age_seconds: 86_400,
        },
    }
}

#[test]
fn qeaa_validates_happy_path() {
    validate_qeaa_compliance(&sample_qeaa(), 1_750_000_000).unwrap();
}

#[test]
fn qeaa_treats_certificate_chain_as_bounded_external_evidence() {
    let mut qeaa = sample_qeaa();
    qeaa.issuer_credential.cert_chain_der = vec![vec![0x01, 0x02, 0x03]];

    validate_qeaa_compliance(&qeaa, 1_750_000_000).unwrap();
}

#[test]
fn qeaa_rejects_non_qeaa_qtsp_role() {
    let mut qeaa = sample_qeaa();
    qeaa.qtsp.tsp_role = QtspRole::Unspecified;

    let err = validate_qeaa_compliance(&qeaa, 1_750_000_000).unwrap_err();

    assert_eq!(
        err,
        QeaaComplianceError::InvalidInput(QeaaInvalidReason::UnsupportedQtspRole)
    );
}

#[test]
fn qeaa_rejects_insufficient_identity_proofing() {
    let mut qeaa = sample_qeaa();
    qeaa.identity_proofing.loip = IdentityProofingLevel::Extended;

    let err = validate_qeaa_compliance(&qeaa, 1_750_000_000).unwrap_err();

    assert_eq!(
        err,
        QeaaComplianceError::InvalidInput(QeaaInvalidReason::InsufficientIdentityProofingLevel)
    );
}

#[test]
fn qeaa_rejects_inactive_audit_period() {
    let qeaa = sample_qeaa();

    let err = validate_qeaa_compliance(&qeaa, 1_900_000_000).unwrap_err();

    assert_eq!(
        err,
        QeaaComplianceError::InvalidInput(QeaaInvalidReason::AuditPeriodNotEffective)
    );
}

#[test]
fn qeaa_rejects_zero_length_audit_period() {
    let mut qeaa = sample_qeaa();
    qeaa.audit.period_to_unix = qeaa.audit.period_from_unix;

    let err = validate_qeaa_compliance(&qeaa, 1_750_000_000).unwrap_err();

    assert_eq!(
        err,
        QeaaComplianceError::InvalidInput(QeaaInvalidReason::InvalidAuditPeriod)
    );
}

#[test]
fn qeaa_rejects_all_zero_digests() {
    let mut qeaa = sample_qeaa();
    qeaa.audit.audit_report_hash = [0; 32];

    let err = validate_qeaa_compliance(&qeaa, 1_750_000_000).unwrap_err();

    assert_eq!(
        err,
        QeaaComplianceError::InvalidInput(QeaaInvalidReason::InvalidField(
            QeaaField::AuditReportHash
        ))
    );
}

#[test]
fn qeaa_rejects_oversized_certificate_chain() {
    let mut qeaa = sample_qeaa();
    qeaa.issuer_credential.cert_chain_der = vec![vec![1]; MAX_CERT_CHAIN_LEN + 1];

    let err = validate_qeaa_compliance(&qeaa, 1_750_000_000).unwrap_err();

    assert_eq!(
        err,
        QeaaComplianceError::InvalidInput(QeaaInvalidReason::FieldTooLarge(
            QeaaField::CertChainDer
        ))
    );
}

#[test]
fn qeaa_rejects_oversized_certificate_chain_total_der() {
    let mut qeaa = sample_qeaa();
    let first_der = vec![1; MAX_CERT_DER_BYTES];
    let second_der = vec![2; MAX_CERT_CHAIN_TOTAL_DER_BYTES - MAX_CERT_DER_BYTES + 1];
    qeaa.issuer_credential.cert_chain_der = vec![first_der, second_der];

    let err = validate_qeaa_compliance(&qeaa, 1_750_000_000).unwrap_err();

    assert_eq!(
        err,
        QeaaComplianceError::InvalidInput(QeaaInvalidReason::FieldTooLarge(
            QeaaField::CertChainDer
        ))
    );
}

#[test]
fn qeaa_rejects_invalid_oid() {
    let mut qeaa = sample_qeaa();
    qeaa.issuer_credential.policy_oids = vec!["0.4.bad".to_owned()];

    let err = validate_qeaa_compliance(&qeaa, 1_750_000_000).unwrap_err();

    assert_eq!(
        err,
        QeaaComplianceError::InvalidInput(QeaaInvalidReason::InvalidField(QeaaField::PolicyOids))
    );
}

#[test]
fn qeaa_rejects_stale_status_policy_window() {
    let mut qeaa = sample_qeaa();
    qeaa.revocation.max_status_age_seconds = 86_401;

    let err = validate_qeaa_compliance(&qeaa, 1_750_000_000).unwrap_err();

    assert_eq!(
        err,
        QeaaComplianceError::InvalidInput(QeaaInvalidReason::FieldTooLarge(
            QeaaField::MaxStatusAgeSeconds
        ))
    );
}

#[test]
fn qeaa_diagnostics_are_redacted_and_owned_material_zeroizes() {
    use zeroize::Zeroize;

    let mut qeaa = sample_qeaa();
    let debug = format!("{qeaa:?}");
    assert!(debug.contains("<redacted>"));
    assert!(!debug.contains("Test QTSP"));
    assert!(!debug.contains("EU:QTSP:123"));

    qeaa.zeroize();
    assert!(qeaa.qtsp.tsp_name.is_empty());
    assert!(qeaa.issuer_credential.cert_chain_der.is_empty());
    assert!(qeaa.identity_proofing.evidence_ref.is_empty());
    assert!(qeaa.audit.audit_report_ref.is_empty());
}
