// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Protocol-neutral QEAA compliance metadata and audit evidence validation.
//!
//! This crate owns local data-model constraints only. It does not fetch trusted
//! lists, verify certificate chains, evaluate signatures, make trust decisions,
//! perform protocol exchange, or record server audit trails. Callers pass
//! already-resolved trust and envelope evidence into this layer for
//! deterministic validation.

mod error;
mod model;
mod provenance;
mod screen_text;
mod validate;

pub use error::{QeaaComplianceError, QeaaField, QeaaInvalidReason};
pub use model::{
    AuditInfo, IdentityProofing, IdentityProofingLevel, IssuerCredential, IssuerCredentialKind,
    KeyManagement, KeyProtection, QeaaCompliance, QeaaPolicies, QeaaValidationPolicy, QtspInfo,
    QtspRole, RevocationPolicy, Sha256Digest, StatusMethod, DEFAULT_MAX_STATUS_AGE_SECONDS,
    MAX_CERT_CHAIN_LEN, MAX_CERT_CHAIN_TOTAL_DER_BYTES, MAX_CERT_DER_BYTES, MAX_OID_COUNT,
    MAX_QEAA_TEXT_BYTES, MAX_STANDARD_COUNT, SHA256_DIGEST_LEN,
};
pub use provenance::{
    validate_verification_provenance, StandardsVersions, VerificationProvenance,
    VerificationProvenanceError, VerificationProvenanceField, VerificationResolvers,
    MAX_PROVENANCE_TEXT_BYTES,
};
pub use validate::{validate_qeaa_compliance, validate_qeaa_compliance_with_policy};
