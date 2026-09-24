// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use zeroize::{Zeroize, ZeroizeOnDrop};

/// SHA-256 digest bytes.
pub type Sha256Digest = [u8; SHA256_DIGEST_LEN];

/// Length of a SHA-256 digest in bytes.
pub const SHA256_DIGEST_LEN: usize = 32;

/// Maximum accepted UTF-8 bytes for identifiers and references in QEAA metadata.
pub const MAX_QEAA_TEXT_BYTES: usize = 2048;

/// Maximum accepted certificate chain length.
pub const MAX_CERT_CHAIN_LEN: usize = 8;

/// Maximum accepted DER bytes for one certificate.
pub const MAX_CERT_DER_BYTES: usize = 64 * 1024;

/// Maximum accepted total DER bytes across one QEAA certificate chain.
pub const MAX_CERT_CHAIN_TOTAL_DER_BYTES: usize = 256 * 1024;

/// Maximum accepted policy or QCStatement OID count.
pub const MAX_OID_COUNT: usize = 32;

/// Maximum accepted policy standard count.
pub const MAX_STANDARD_COUNT: usize = 16;

/// Default maximum age for QEAA status evidence.
pub const DEFAULT_MAX_STATUS_AGE_SECONDS: u32 = 86_400;

/// Identity proofing level asserted by QEAA compliance evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Zeroize)]
pub enum IdentityProofingLevel {
    /// Boundary value for proto/JSON interop; never valid QEAA evidence.
    Unspecified,

    /// Baseline proofing level.
    Baseline,

    /// Extended proofing level.
    Extended,

    /// High proofing level.
    High,
}

impl IdentityProofingLevel {
    /// Stable rank used for policy comparisons.
    pub const fn rank(self) -> u8 {
        match self {
            Self::Unspecified => 0,
            Self::Baseline => 1,
            Self::Extended => 2,
            Self::High => 3,
        }
    }
}

/// QTSP role for the service issuing or attesting QEAA credentials.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Zeroize)]
pub enum QtspRole {
    /// Boundary value for interop; never valid QEAA evidence.
    Unspecified,

    /// Qualified Electronic Attestation of Attributes provider.
    QeaaProvider,
}

/// Issuer credential family used to bind the QEAA issuer to trust material.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Zeroize)]
pub enum IssuerCredentialKind {
    /// Boundary value for interop; never valid QEAA evidence.
    Unspecified,

    /// X.509 certificate chain and trusted-list evidence.
    X509,
}

/// Key protection class for the credential signing key.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Zeroize)]
pub enum KeyProtection {
    /// Boundary value for interop; never valid QEAA evidence.
    Unspecified,

    /// Hardware security module.
    Hsm,

    /// Qualified signature creation device or equivalent qualified protection.
    Qscd,
}

/// Revocation status method declared for a QEAA credential.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Zeroize)]
pub enum StatusMethod {
    /// Boundary value for interop; never valid QEAA evidence.
    Unspecified,

    /// W3C/EUDI-compatible status-list evidence.
    StatusList,
}

/// Complete protocol-neutral QEAA compliance evidence.
#[derive(Eq, PartialEq, Zeroize, ZeroizeOnDrop)]
pub struct QeaaCompliance {
    /// Qualified trust service provider metadata.
    pub qtsp: QtspInfo,

    /// Policy identifiers and standards asserted for the QEAA.
    pub policies: QeaaPolicies,

    /// Issuer trust material metadata.
    pub issuer_credential: IssuerCredential,

    /// Credential signing key management evidence.
    pub key_management: KeyManagement,

    /// Identity proofing evidence.
    pub identity_proofing: IdentityProofing,

    /// Audit report evidence and validity period.
    pub audit: AuditInfo,

    /// Revocation/status policy for the QEAA.
    pub revocation: RevocationPolicy,
}

/// Qualified trust service provider metadata.
#[derive(Eq, PartialEq, Zeroize, ZeroizeOnDrop)]
pub struct QtspInfo {
    /// QTSP display or registered name. Treat as untrusted display data at boundaries.
    pub tsp_name: String,

    /// Stable QTSP identifier from the caller's trust registry or TSL projection.
    pub tsp_id: String,

    /// QTSP role asserted for this credential.
    pub tsp_role: QtspRole,
}

/// QEAA policy identifiers and referenced standards.
#[derive(Eq, PartialEq, Zeroize, ZeroizeOnDrop)]
pub struct QeaaPolicies {
    /// Policy identifier asserted for the QEAA profile.
    pub policy_id: String,

    /// Standards or profiles claimed by the issuer.
    pub standards: Vec<String>,
}

/// Issuer trust material metadata.
#[derive(Eq, PartialEq, Zeroize, ZeroizeOnDrop)]
pub struct IssuerCredential {
    /// Credential trust-material family.
    pub kind: IssuerCredentialKind,

    /// SHA-256 fingerprint of the issuing certificate.
    pub cert_fingerprint_sha256: Sha256Digest,

    /// DER-encoded certificate chain, leaf first.
    pub cert_chain_der: Vec<Vec<u8>>,

    /// Trusted-list reference used to establish the issuer's qualified status.
    pub trusted_list_ref: String,

    /// Certificate policy OIDs asserted for the issuer.
    pub policy_oids: Vec<String>,

    /// QCStatement OIDs asserted for the issuer.
    pub qcstatements_oids: Vec<String>,
}

/// Credential signing key management metadata.
#[derive(Eq, PartialEq, Zeroize, ZeroizeOnDrop)]
pub struct KeyManagement {
    /// Stable key identifier used for signing and status evidence.
    pub signing_key_id: String,

    /// Protection class for the signing key.
    pub protection: KeyProtection,
}

/// Identity proofing evidence metadata.
#[derive(Eq, PartialEq, Zeroize, ZeroizeOnDrop)]
pub struct IdentityProofing {
    /// Proofing standard used by the provider.
    pub standard: String,

    /// Level of identity proofing.
    pub loip: IdentityProofingLevel,

    /// Opaque reference to proofing evidence held outside the credential.
    pub evidence_ref: String,

    /// SHA-256 hash of proofing evidence.
    pub evidence_hash: Sha256Digest,
}

/// Audit report evidence and validity window.
#[derive(Eq, PartialEq, Zeroize, ZeroizeOnDrop)]
pub struct AuditInfo {
    /// Audit standard used for the report.
    pub audit_standard: String,

    /// Opaque audit report reference.
    pub audit_report_ref: String,

    /// SHA-256 hash of the audit report.
    pub audit_report_hash: Sha256Digest,

    /// Inclusive audit period start as Unix seconds.
    pub period_from_unix: u64,

    /// Inclusive audit period end as Unix seconds.
    pub period_to_unix: u64,
}

/// Revocation policy metadata for QEAA credentials.
#[derive(Eq, PartialEq, Zeroize, ZeroizeOnDrop)]
pub struct RevocationPolicy {
    /// Status method used by the credential.
    pub status_method: StatusMethod,

    /// Key identifier for status-list signing evidence.
    pub signing_key_id: String,

    /// Maximum accepted age for status evidence.
    pub max_status_age_seconds: u32,
}

// QEAA metadata contains organization identifiers, evidence references, key
// identifiers, and certificate material. A single deliberately uniform Debug
// policy prevents a newly added field from being exposed accidentally.
macro_rules! impl_redacted_debug {
    ($($type_name:ty),+ $(,)?) => {
        $(
            impl core::fmt::Debug for $type_name {
                fn fmt(
                    &self,
                    formatter: &mut core::fmt::Formatter<'_>,
                ) -> core::fmt::Result {
                    formatter
                        .debug_struct(stringify!($type_name))
                        .field("contents", &"<redacted>")
                        .finish()
                }
            }
        )+
    };
}

impl_redacted_debug!(
    QeaaCompliance,
    QtspInfo,
    QeaaPolicies,
    IssuerCredential,
    KeyManagement,
    IdentityProofing,
    AuditInfo,
    RevocationPolicy,
);

/// Local validation policy for QEAA compliance evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QeaaValidationPolicy {
    /// Verification time in Unix seconds.
    pub now_unix: u64,

    /// Minimum accepted identity proofing level.
    pub min_identity_proofing_level: IdentityProofingLevel,

    /// Maximum accepted status evidence age.
    pub max_status_age_seconds: u32,

    /// When true, the audit report period must cover `now_unix`.
    pub require_current_audit_period: bool,
}

impl QeaaValidationPolicy {
    /// Strict QEAA policy for verifier-side evaluation.
    pub const fn strict(now_unix: u64) -> Self {
        Self {
            now_unix,
            min_identity_proofing_level: IdentityProofingLevel::High,
            max_status_age_seconds: DEFAULT_MAX_STATUS_AGE_SECONDS,
            require_current_audit_period: true,
        }
    }
}
