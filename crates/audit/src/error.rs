// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_ssi_proto::generated::proto::reallyme::identity_core::v1::IdentityCoreErrorReason;
use thiserror::Error;

/// QEAA compliance fields referenced by validation errors.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum QeaaField {
    /// `qtsp.tsp_name`.
    #[error("qtsp.tsp_name")]
    QtspName,

    /// `qtsp.tsp_id`.
    #[error("qtsp.tsp_id")]
    QtspId,

    /// `qtsp.tsp_role`.
    #[error("qtsp.tsp_role")]
    QtspRole,

    /// `policies.policy_id`.
    #[error("policies.policy_id")]
    PolicyId,

    /// `policies.standards`.
    #[error("policies.standards")]
    PolicyStandards,

    /// `issuer_credential.kind`.
    #[error("issuer_credential.kind")]
    IssuerCredentialKind,

    /// `issuer_credential.cert_fingerprint_sha256`.
    #[error("issuer_credential.cert_fingerprint_sha256")]
    CertFingerprintSha256,

    /// `issuer_credential.cert_chain_der`.
    #[error("issuer_credential.cert_chain_der")]
    CertChainDer,

    /// `issuer_credential.trusted_list_ref`.
    #[error("issuer_credential.trusted_list_ref")]
    TrustedListRef,

    /// `issuer_credential.policy_oids`.
    #[error("issuer_credential.policy_oids")]
    PolicyOids,

    /// `issuer_credential.qcstatements_oids`.
    #[error("issuer_credential.qcstatements_oids")]
    QcStatementsOids,

    /// `key_management.signing_key_id`.
    #[error("key_management.signing_key_id")]
    SigningKeyId,

    /// `key_management.protection`.
    #[error("key_management.protection")]
    KeyProtection,

    /// `identity_proofing.standard`.
    #[error("identity_proofing.standard")]
    IdentityProofingStandard,

    /// `identity_proofing.loip`.
    #[error("identity_proofing.loip")]
    IdentityProofingLevel,

    /// `identity_proofing.evidence_ref`.
    #[error("identity_proofing.evidence_ref")]
    EvidenceRef,

    /// `identity_proofing.evidence_hash`.
    #[error("identity_proofing.evidence_hash")]
    EvidenceHash,

    /// `audit.audit_standard`.
    #[error("audit.audit_standard")]
    AuditStandard,

    /// `audit.audit_report_ref`.
    #[error("audit.audit_report_ref")]
    AuditReportRef,

    /// `audit.audit_report_hash`.
    #[error("audit.audit_report_hash")]
    AuditReportHash,

    /// `audit.period`.
    #[error("audit.period")]
    AuditPeriod,

    /// `revocation.status_method`.
    #[error("revocation.status_method")]
    RevocationStatusMethod,

    /// `revocation.max_status_age_seconds`.
    #[error("revocation.max_status_age_seconds")]
    MaxStatusAgeSeconds,
}

/// Stable reason codes for invalid QEAA compliance evidence.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum QeaaInvalidReason {
    /// A required field is absent or empty after trimming.
    #[error("missing required QEAA field")]
    MissingField(QeaaField),

    /// A field is present but fails local structural validation.
    #[error("invalid QEAA field")]
    InvalidField(QeaaField),

    /// A collection exceeds the accepted SDK/core bound.
    #[error("QEAA field exceeds accepted bounds")]
    FieldTooLarge(QeaaField),

    /// The QTSP role is not the QEAA provider role required for QEAA evidence.
    #[error("unsupported QTSP role")]
    UnsupportedQtspRole,

    /// The issuer credential kind is not X.509.
    #[error("unsupported issuer credential kind")]
    UnsupportedIssuerCredentialKind,

    /// The signing key protection class is not accepted for QEAA issuing keys.
    #[error("unsupported key protection")]
    UnsupportedKeyProtection,

    /// The identity proofing level is unspecified or below policy.
    #[error("insufficient identity proofing level")]
    InsufficientIdentityProofingLevel,

    /// The revocation method is not accepted for QEAA status evidence.
    #[error("unsupported revocation status method")]
    UnsupportedStatusMethod,

    /// The audit period is absent, zero, or not ordered.
    #[error("invalid audit period")]
    InvalidAuditPeriod,

    /// The audit report does not cover the requested verification time.
    #[error("audit period is not effective")]
    AuditPeriodNotEffective,
}

/// QEAA compliance validation errors.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum QeaaComplianceError {
    /// The compliance structure failed deterministic local validation.
    #[error("invalid QEAA compliance evidence")]
    InvalidInput(QeaaInvalidReason),
}

impl From<QeaaInvalidReason> for IdentityCoreErrorReason {
    fn from(reason: QeaaInvalidReason) -> Self {
        match reason {
            QeaaInvalidReason::MissingField(_) => {
                Self::IDENTITY_CORE_ERROR_REASON_QEAA_MISSING_FIELD
            }
            QeaaInvalidReason::InvalidField(_) => {
                Self::IDENTITY_CORE_ERROR_REASON_QEAA_INVALID_FIELD
            }
            QeaaInvalidReason::FieldTooLarge(_) => {
                Self::IDENTITY_CORE_ERROR_REASON_QEAA_FIELD_TOO_LARGE
            }
            QeaaInvalidReason::UnsupportedQtspRole => {
                Self::IDENTITY_CORE_ERROR_REASON_QEAA_UNSUPPORTED_QTSP_ROLE
            }
            QeaaInvalidReason::UnsupportedIssuerCredentialKind => {
                Self::IDENTITY_CORE_ERROR_REASON_QEAA_UNSUPPORTED_ISSUER_CREDENTIAL_KIND
            }
            QeaaInvalidReason::UnsupportedKeyProtection => {
                Self::IDENTITY_CORE_ERROR_REASON_QEAA_UNSUPPORTED_KEY_PROTECTION
            }
            QeaaInvalidReason::InsufficientIdentityProofingLevel => {
                Self::IDENTITY_CORE_ERROR_REASON_QEAA_INSUFFICIENT_IDENTITY_PROOFING_LEVEL
            }
            QeaaInvalidReason::UnsupportedStatusMethod => {
                Self::IDENTITY_CORE_ERROR_REASON_QEAA_UNSUPPORTED_STATUS_METHOD
            }
            QeaaInvalidReason::InvalidAuditPeriod => {
                Self::IDENTITY_CORE_ERROR_REASON_QEAA_INVALID_AUDIT_PERIOD
            }
            QeaaInvalidReason::AuditPeriodNotEffective => {
                Self::IDENTITY_CORE_ERROR_REASON_QEAA_AUDIT_PERIOD_NOT_EFFECTIVE
            }
        }
    }
}

impl From<QeaaComplianceError> for IdentityCoreErrorReason {
    fn from(error: QeaaComplianceError) -> Self {
        match error {
            QeaaComplianceError::InvalidInput(reason) => reason.into(),
        }
    }
}

#[cfg(test)]
#[path = "error_proto_error_tests.rs"]
mod proto_error_tests;
