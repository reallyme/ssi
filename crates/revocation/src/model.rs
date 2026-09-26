// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_trust_x509::X509Certificate;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::{RevocationPolicyError, StatusCheckError};

/// Default maximum age for an OCSP `thisUpdate` when no tighter profile is supplied.
pub const DEFAULT_MAX_OCSP_AGE_SECS: u64 = 86_400;

/// Default clock-skew allowance for OCSP freshness checks.
pub const DEFAULT_OCSP_ALLOWED_SKEW_SECS: u64 = 300;

/// Behavior when a revocation source cannot produce a terminal answer.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum SoftFailMode {
    /// Treat unavailable/expired/invalid evidence as terminal failure.
    Strict,

    /// Try the next configured source only when the current source reports
    /// [`StatusCheckError::Unavailable`] (no evidence could be obtained).
    ///
    /// Evidence that was obtained but is expired, not yet valid, malformed,
    /// badly signed, or reported as unknown remains terminal.
    FallbackOnUnavailable,

    /// Try the next configured source when evidence is unavailable or invalid.
    Fallback,
}

/// Portable OCSP policy knobs enforced after a backend parses/verifies OCSP.
///
/// This is the single OCSP policy type shared by the composite policy and the
/// portable OCSP checker, so a [`CompositeRevocationPolicy::ocsp`] value can be
/// applied to the checker without conversion.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct OcspPolicy {
    /// If true, missing `nextUpdate` is invalid.
    pub require_next_update: bool,

    /// Maximum accepted `thisUpdate` age in seconds. If `None`, no local
    /// ceiling is enforced beyond `nextUpdate`.
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
            // RFC 6960 Section 4.2.2.1 permits nextUpdate to be absent, but a
            // relying party still needs a local freshness ceiling to prevent
            // indefinite replay of an otherwise valid response.
            max_age_secs: Some(DEFAULT_MAX_OCSP_AGE_SECS),
            allowed_skew_secs: DEFAULT_OCSP_ALLOWED_SKEW_SECS,
            require_verified: true,
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
    ///
    /// The composite checker delegates to an already-built OCSP checker, so
    /// this policy takes effect when that checker is built from it (for
    /// example `OcspChecker::from_composite_policy` in the OCSP core crate).
    pub ocsp: OcspPolicy,
}

impl CompositeRevocationPolicy {
    /// Build a permissive fallback policy for local testing and interoperability work.
    pub fn fallback(now: OffsetDateTime) -> Result<Self, RevocationPolicyError> {
        Ok(Self {
            prefer_ocsp: true,
            prefer_crl: true,
            prefer_statuslist: true,
            soft_fail: SoftFailMode::Fallback,
            now_unix: u64::try_from(now.unix_timestamp())
                .map_err(|_| RevocationPolicyError::InvalidEvaluationTime)?,
            ocsp: OcspPolicy::default(),
        })
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
///
/// Evidence without an expiry is never cached: every cached outcome must carry
/// the freshness bound derived from the evidence itself (for example CRL
/// `nextUpdate` or OCSP `nextUpdate`).
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
