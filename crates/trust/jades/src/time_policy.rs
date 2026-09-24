// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use time::{format_description::well_known::Rfc3339, OffsetDateTime};

use crate::header::ProtectedHeader;
use crate::{
    ClaimedSigningTime, ClaimedSigningTimeKind, JadesError, JadesErrorReason, JadesPolicy,
};

// ETSI TS 119 182-1 v1.2.1 §5.1.11 makes `iat` mandatory for signatures
// created on or after 2025-07-15T00:00:00Z and §5.2.1 retains `sigT` only for
// validation of signatures created before that transition.
const IAT_TRANSITION_UNIX_SECONDS: i64 = 1_752_537_600;
const STRICT_SIGNATURE_TIME_BYTES: usize = 20;

pub(crate) fn validate_claimed_signing_time(
    header: &ProtectedHeader,
    now: OffsetDateTime,
    policy: &JadesPolicy,
) -> Result<ClaimedSigningTime, JadesError> {
    let claimed = match (header.issued_at, header.signature_time.as_deref()) {
        (Some(_), Some(_)) => {
            return Err(JadesError::new(JadesErrorReason::InvalidClaimedSigningTime));
        }
        (Some(timestamp), None) => ClaimedSigningTime {
            kind: ClaimedSigningTimeKind::IssuedAt,
            value: OffsetDateTime::from_unix_timestamp(timestamp)
                .map_err(|_| JadesError::new(JadesErrorReason::InvalidClaimedSigningTime))?,
        },
        (None, Some(value)) => {
            if !is_strict_utc_signature_time(value.as_bytes()) {
                return Err(JadesError::new(JadesErrorReason::InvalidClaimedSigningTime));
            }
            let parsed = OffsetDateTime::parse(value, &Rfc3339)
                .map_err(|_| JadesError::new(JadesErrorReason::InvalidClaimedSigningTime))?;
            if parsed.unix_timestamp() >= IAT_TRANSITION_UNIX_SECONDS {
                return Err(JadesError::new(JadesErrorReason::SigningTimeOutsidePolicy));
            }
            ClaimedSigningTime {
                kind: ClaimedSigningTimeKind::LegacySignatureTime,
                value: parsed,
            }
        }
        (None, None) => {
            return Err(JadesError::new(JadesErrorReason::MissingClaimedSigningTime));
        }
    };

    let skew = i64::from(policy.maximum_future_skew_seconds);
    let latest = now
        .unix_timestamp()
        .checked_add(skew)
        .ok_or_else(|| JadesError::new(JadesErrorReason::SigningTimeOutsidePolicy))?;
    if claimed.value.unix_timestamp() > latest {
        return Err(JadesError::new(JadesErrorReason::SigningTimeOutsidePolicy));
    }

    Ok(claimed)
}

fn is_strict_utc_signature_time(value: &[u8]) -> bool {
    value.len() == STRICT_SIGNATURE_TIME_BYTES
        && value.get(4) == Some(&b'-')
        && value.get(7) == Some(&b'-')
        && value.get(10) == Some(&b'T')
        && value.get(13) == Some(&b':')
        && value.get(16) == Some(&b':')
        && value.get(19) == Some(&b'Z')
        && value.iter().enumerate().all(|(index, byte)| {
            matches!(index, 4 | 7 | 10 | 13 | 16 | 19) || byte.is_ascii_digit()
        })
}
