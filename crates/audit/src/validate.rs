// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::{
    IdentityProofing, IdentityProofingLevel, IssuerCredential, IssuerCredentialKind, KeyManagement,
    KeyProtection, QeaaCompliance, QeaaComplianceError, QeaaField, QeaaInvalidReason, QeaaPolicies,
    QeaaValidationPolicy, QtspInfo, QtspRole, RevocationPolicy, StatusMethod, MAX_CERT_CHAIN_LEN,
    MAX_CERT_CHAIN_TOTAL_DER_BYTES, MAX_CERT_DER_BYTES, MAX_OID_COUNT, MAX_QEAA_TEXT_BYTES,
    MAX_STANDARD_COUNT,
};

type Result<T> = core::result::Result<T, QeaaComplianceError>;

/// Validate QEAA compliance evidence using strict verifier defaults.
pub fn validate_qeaa_compliance(compliance: &QeaaCompliance, now_unix: u64) -> Result<()> {
    validate_qeaa_compliance_with_policy(compliance, QeaaValidationPolicy::strict(now_unix))
}

/// Validate QEAA compliance evidence using caller-supplied local policy.
///
/// This is intentionally non-cryptographic and non-I/O. Certificate chain
/// validation, trusted-list fetching, and signature verification are owned by
/// trust and envelope crates before their verified result is projected here.
pub fn validate_qeaa_compliance_with_policy(
    compliance: &QeaaCompliance,
    policy: QeaaValidationPolicy,
) -> Result<()> {
    validate_qtsp(&compliance.qtsp)?;
    validate_policies(&compliance.policies)?;
    validate_issuer_credential(&compliance.issuer_credential)?;
    validate_key_management(&compliance.key_management)?;
    validate_identity_proofing(&compliance.identity_proofing, policy)?;
    validate_audit_info(&compliance.audit, policy)?;
    validate_revocation_policy(&compliance.revocation, policy)?;
    Ok(())
}

fn invalid(reason: QeaaInvalidReason) -> QeaaComplianceError {
    QeaaComplianceError::InvalidInput(reason)
}

fn validate_text(value: &str, field: QeaaField) -> Result<()> {
    if value.trim().is_empty() {
        return Err(invalid(QeaaInvalidReason::MissingField(field)));
    }

    if value.len() > MAX_QEAA_TEXT_BYTES {
        return Err(invalid(QeaaInvalidReason::FieldTooLarge(field)));
    }

    Ok(())
}

fn validate_digest(bytes: &[u8], field: QeaaField) -> Result<()> {
    if bytes.iter().all(|byte| *byte == 0) {
        return Err(invalid(QeaaInvalidReason::InvalidField(field)));
    }
    Ok(())
}

fn validate_oid(value: &str, field: QeaaField) -> Result<()> {
    validate_text(value, field)?;

    let mut saw_digit = false;
    let mut saw_dot = false;
    let mut previous_was_dot = true;
    let bytes = value.as_bytes();
    if !matches!(bytes.first(), Some(b'0' | b'1' | b'2')) {
        return Err(invalid(QeaaInvalidReason::InvalidField(field)));
    }

    for byte in bytes {
        match byte {
            b'0'..=b'9' => {
                saw_digit = true;
                previous_was_dot = false;
            }
            b'.' if !previous_was_dot => {
                saw_dot = true;
                previous_was_dot = true;
            }
            _ => return Err(invalid(QeaaInvalidReason::InvalidField(field))),
        }
    }

    if !saw_digit || !saw_dot || previous_was_dot {
        return Err(invalid(QeaaInvalidReason::InvalidField(field)));
    }

    Ok(())
}

fn validate_qtsp(qtsp: &QtspInfo) -> Result<()> {
    validate_text(&qtsp.tsp_name, QeaaField::QtspName)?;
    validate_text(&qtsp.tsp_id, QeaaField::QtspId)?;

    match qtsp.tsp_role {
        QtspRole::QeaaProvider => Ok(()),
        QtspRole::Unspecified => Err(invalid(QeaaInvalidReason::UnsupportedQtspRole)),
    }
}

fn validate_policies(policies: &QeaaPolicies) -> Result<()> {
    validate_text(&policies.policy_id, QeaaField::PolicyId)?;

    if policies.standards.is_empty() {
        return Err(invalid(QeaaInvalidReason::MissingField(
            QeaaField::PolicyStandards,
        )));
    }

    if policies.standards.len() > MAX_STANDARD_COUNT {
        return Err(invalid(QeaaInvalidReason::FieldTooLarge(
            QeaaField::PolicyStandards,
        )));
    }

    for standard in &policies.standards {
        validate_text(standard, QeaaField::PolicyStandards)?;
    }

    Ok(())
}

fn validate_issuer_credential(issuer: &IssuerCredential) -> Result<()> {
    match issuer.kind {
        IssuerCredentialKind::X509 => {}
        IssuerCredentialKind::Unspecified => {
            return Err(invalid(QeaaInvalidReason::UnsupportedIssuerCredentialKind));
        }
    }

    validate_digest(
        &issuer.cert_fingerprint_sha256,
        QeaaField::CertFingerprintSha256,
    )?;

    if issuer.cert_chain_der.is_empty() {
        return Err(invalid(QeaaInvalidReason::MissingField(
            QeaaField::CertChainDer,
        )));
    }

    if issuer.cert_chain_der.len() > MAX_CERT_CHAIN_LEN {
        return Err(invalid(QeaaInvalidReason::FieldTooLarge(
            QeaaField::CertChainDer,
        )));
    }

    let mut total_der_bytes = 0_usize;
    for der in &issuer.cert_chain_der {
        if der.is_empty() {
            return Err(invalid(QeaaInvalidReason::InvalidField(
                QeaaField::CertChainDer,
            )));
        }
        if der.len() > MAX_CERT_DER_BYTES {
            return Err(invalid(QeaaInvalidReason::FieldTooLarge(
                QeaaField::CertChainDer,
            )));
        }
        total_der_bytes = total_der_bytes.checked_add(der.len()).ok_or(invalid(
            QeaaInvalidReason::FieldTooLarge(QeaaField::CertChainDer),
        ))?;
        if total_der_bytes > MAX_CERT_CHAIN_TOTAL_DER_BYTES {
            return Err(invalid(QeaaInvalidReason::FieldTooLarge(
                QeaaField::CertChainDer,
            )));
        }
    }

    validate_text(&issuer.trusted_list_ref, QeaaField::TrustedListRef)?;

    if issuer.policy_oids.len() > MAX_OID_COUNT {
        return Err(invalid(QeaaInvalidReason::FieldTooLarge(
            QeaaField::PolicyOids,
        )));
    }
    for oid in &issuer.policy_oids {
        validate_oid(oid, QeaaField::PolicyOids)?;
    }

    if issuer.qcstatements_oids.len() > MAX_OID_COUNT {
        return Err(invalid(QeaaInvalidReason::FieldTooLarge(
            QeaaField::QcStatementsOids,
        )));
    }
    for oid in &issuer.qcstatements_oids {
        validate_oid(oid, QeaaField::QcStatementsOids)?;
    }

    Ok(())
}

fn validate_key_management(keys: &KeyManagement) -> Result<()> {
    validate_text(&keys.signing_key_id, QeaaField::SigningKeyId)?;

    match keys.protection {
        KeyProtection::Hsm | KeyProtection::Qscd => Ok(()),
        KeyProtection::Unspecified => Err(invalid(QeaaInvalidReason::UnsupportedKeyProtection)),
    }
}

fn validate_identity_proofing(
    proofing: &IdentityProofing,
    policy: QeaaValidationPolicy,
) -> Result<()> {
    validate_text(&proofing.standard, QeaaField::IdentityProofingStandard)?;
    validate_text(&proofing.evidence_ref, QeaaField::EvidenceRef)?;
    validate_digest(&proofing.evidence_hash, QeaaField::EvidenceHash)?;

    if proofing.loip == IdentityProofingLevel::Unspecified
        || proofing.loip.rank() < policy.min_identity_proofing_level.rank()
    {
        return Err(invalid(
            QeaaInvalidReason::InsufficientIdentityProofingLevel,
        ));
    }

    Ok(())
}

fn validate_audit_info(audit: &crate::AuditInfo, policy: QeaaValidationPolicy) -> Result<()> {
    validate_text(&audit.audit_standard, QeaaField::AuditStandard)?;
    validate_text(&audit.audit_report_ref, QeaaField::AuditReportRef)?;
    validate_digest(&audit.audit_report_hash, QeaaField::AuditReportHash)?;

    if audit.period_from_unix == 0
        || audit.period_to_unix == 0
        || audit.period_from_unix >= audit.period_to_unix
    {
        return Err(invalid(QeaaInvalidReason::InvalidAuditPeriod));
    }

    if policy.require_current_audit_period
        && (policy.now_unix < audit.period_from_unix || policy.now_unix > audit.period_to_unix)
    {
        return Err(invalid(QeaaInvalidReason::AuditPeriodNotEffective));
    }

    Ok(())
}

fn validate_revocation_policy(
    revocation: &RevocationPolicy,
    policy: QeaaValidationPolicy,
) -> Result<()> {
    match revocation.status_method {
        StatusMethod::StatusList => {}
        StatusMethod::Unspecified => {
            return Err(invalid(QeaaInvalidReason::UnsupportedStatusMethod));
        }
    }

    validate_text(&revocation.signing_key_id, QeaaField::SigningKeyId)?;

    if revocation.max_status_age_seconds == 0 {
        return Err(invalid(QeaaInvalidReason::InvalidField(
            QeaaField::MaxStatusAgeSeconds,
        )));
    }

    if revocation.max_status_age_seconds > policy.max_status_age_seconds {
        return Err(invalid(QeaaInvalidReason::FieldTooLarge(
            QeaaField::MaxStatusAgeSeconds,
        )));
    }

    Ok(())
}
