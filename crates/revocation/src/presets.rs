// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use time::OffsetDateTime;

use crate::{CompositeRevocationPolicy, OcspPolicy, SoftFailMode};

const DEFAULT_OCSP_SKEW_SECONDS: u64 = 300;
const EU_QTSP_OCSP_MAX_AGE_SECONDS: u64 = 6 * 60 * 60;

/// eIDAS/QTSP-oriented X.509 revocation policy: OCSP first, CRL fallback, strict failures.
pub fn eu_qtsp_x509(now: OffsetDateTime) -> CompositeRevocationPolicy {
    CompositeRevocationPolicy {
        prefer_ocsp: true,
        prefer_crl: true,
        prefer_statuslist: false,
        soft_fail: SoftFailMode::Strict,
        now_unix: unix_seconds_or_zero(now),
        ocsp: OcspPolicy {
            require_next_update: true,
            max_age_secs: Some(EU_QTSP_OCSP_MAX_AGE_SECONDS),
            allowed_skew_secs: DEFAULT_OCSP_SKEW_SECONDS,
            require_verified: true,
        },
    }
}

/// VC-native revocation policy: StatusList only and strict failures.
pub fn vc_statuslist(now: OffsetDateTime) -> CompositeRevocationPolicy {
    CompositeRevocationPolicy {
        prefer_ocsp: false,
        prefer_crl: false,
        prefer_statuslist: true,
        soft_fail: SoftFailMode::Strict,
        now_unix: unix_seconds_or_zero(now),
        ocsp: OcspPolicy::default(),
    }
}

/// Opt-in hybrid policy: OCSP, CRL, then StatusList with fallback on non-terminal errors.
pub fn hybrid_fallback(now: OffsetDateTime) -> CompositeRevocationPolicy {
    CompositeRevocationPolicy::fallback(now)
}

fn unix_seconds_or_zero(now: OffsetDateTime) -> u64 {
    u64::try_from(now.unix_timestamp()).unwrap_or(0)
}
