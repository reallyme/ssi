// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_trust_x509::X509Certificate;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::StatusCheckError;

/// Behavior when a revocation source cannot produce a terminal answer.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum SoftFailMode {
    /// Treat unavailable/expired/invalid evidence as terminal failure.
    Strict,

    /// Try the next configured source when evidence is unavailable or invalid.
    Fallback,
}

/// Portable OCSP policy knobs enforced after a backend parses/verifies OCSP.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct OcspPolicy {
    /// If true, missing `nextUpdate` is invalid.
    pub require_next_update: bool,

    /// Maximum accepted `thisUpdate` age in seconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_age_secs: Option<u64>,

    /// Clock skew allowance in seconds.
    pub allowed_skew_secs: u64,

    /// If true, backend metadata must prove response signature and responder authorization.
    pub require_verified: bool,
}

impl Default for OcspPolicy {
    fn default() -> Self {
        Self {
            require_next_update: false,
            max_age_secs: None,
            allowed_skew_secs: 300,
            require_verified: false,
        }
    }
}

/// Composite revocation evaluation order and failure handling.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CompositeRevocationPolicy {
    /// Try OCSP evidence when an OCSP checker is configured.
    pub prefer_ocsp: bool,

    /// Try CRL evidence when a CRL checker is configured.
    pub prefer_crl: bool,

    /// Try credential status-list evidence when configured.
    pub prefer_statuslist: bool,

    /// Failover behavior for non-terminal source failures.
    pub soft_fail: SoftFailMode,

    /// Verification time in Unix seconds.
    pub now_unix: u64,

    /// OCSP evidence policy.
    pub ocsp: OcspPolicy,
}

impl CompositeRevocationPolicy {
    /// Build a permissive fallback policy for local testing and interoperability work.
    pub fn fallback(now: OffsetDateTime) -> Self {
        Self {
            prefer_ocsp: true,
            prefer_crl: true,
            prefer_statuslist: true,
            soft_fail: SoftFailMode::Fallback,
            now_unix: u64::try_from(now.unix_timestamp()).unwrap_or(0),
            ocsp: OcspPolicy::default(),
        }
    }
}

/// What kind of revocation evidence produced a cached result.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum RevocationSource {
    /// OCSP evidence.
    Ocsp,

    /// CRL evidence.
    Crl,

    /// VC status-list evidence.
    StatusList,
}

/// Cached revocation evidence metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RevocationEvidenceMeta {
    /// When this evidence was fetched or parsed.
    pub fetched_at_unix: u64,

    /// When this evidence expires.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at_unix: Option<u64>,

    /// Evidence source type.
    pub source: RevocationSource,
}

/// Trait for revocation and suspension status sources.
pub trait StatusChecker {
    /// Check status for an already-parsed certificate or credential context.
    fn check(&self, cert: &X509Certificate, now_unix: u64) -> Result<(), StatusCheckError>;
}
