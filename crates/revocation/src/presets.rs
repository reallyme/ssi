// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use time::OffsetDateTime;

use crate::model::DEFAULT_OCSP_ALLOWED_SKEW_SECS;
use crate::{CompositeRevocationPolicy, OcspPolicy, RevocationPolicyError, SoftFailMode};

const EU_QTSP_OCSP_MAX_AGE_SECONDS: u64 = 6 * 60 * 60;

/// eIDAS/QTSP-oriented X.509 revocation policy.
///
/// OCSP is consulted first. CRL is consulted only when OCSP evidence is
/// unavailable; OCSP evidence that was obtained but is stale, malformed,
/// unverified, or reports `unknown` is a terminal failure.
pub fn eu_qtsp_x509(
    now: OffsetDateTime,
) -> Result<CompositeRevocationPolicy, RevocationPolicyError> {
    Ok(CompositeRevocationPolicy {
        prefer_ocsp: true,
        prefer_crl: true,
        prefer_statuslist: false,
        soft_fail: SoftFailMode::FallbackOnUnavailable,
        now_unix: unix_seconds(now)?,
        ocsp: OcspPolicy {
            require_next_update: true,
            max_age_secs: Some(EU_QTSP_OCSP_MAX_AGE_SECONDS),
            allowed_skew_secs: DEFAULT_OCSP_ALLOWED_SKEW_SECS,
            require_verified: true,
        },
    })
}

/// VC-native revocation policy: StatusList only and strict failures.
pub fn vc_statuslist(
    now: OffsetDateTime,
) -> Result<CompositeRevocationPolicy, RevocationPolicyError> {
    Ok(CompositeRevocationPolicy {
        prefer_ocsp: false,
        prefer_crl: false,
        prefer_statuslist: true,
        soft_fail: SoftFailMode::Strict,
        now_unix: unix_seconds(now)?,
        ocsp: OcspPolicy::default(),
    })
}

/// Opt-in hybrid policy: OCSP, CRL, then StatusList with fallback on non-terminal errors.
pub fn hybrid_fallback(
    now: OffsetDateTime,
) -> Result<CompositeRevocationPolicy, RevocationPolicyError> {
    CompositeRevocationPolicy::fallback(now)
}

fn unix_seconds(now: OffsetDateTime) -> Result<u64, RevocationPolicyError> {
    u64::try_from(now.unix_timestamp()).map_err(|_| RevocationPolicyError::InvalidEvaluationTime)
}
