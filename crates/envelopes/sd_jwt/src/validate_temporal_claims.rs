// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Verification-time validation of SD-JWT credential temporal claims.

use serde_json::Value;

use crate::SdJwtEnvelopeError;

/// Maximum symmetric clock skew a verifier may configure for `exp`, `nbf`,
/// and future `iat` checks.
pub const MAX_SD_JWT_CLOCK_SKEW_SECONDS: u64 = 300;

/// Default symmetric clock skew applied by [`crate::SdJwtVerificationOptions::new`].
pub const DEFAULT_SD_JWT_CLOCK_SKEW_SECONDS: u64 = 60;

const ISSUED_AT_CLAIM_NAME: &str = "iat";
const NOT_BEFORE_CLAIM_NAME: &str = "nbf";
const EXPIRATION_CLAIM_NAME: &str = "exp";

/// Validate the credential validity window against the verifier's clock.
///
/// `exp` and `nbf` are read from the issuer-signed payload because they are
/// never selectively disclosable. `iat` may be selectively disclosed under
/// SD-JWT VC, so it is read from the authenticated resolved payload. Absent
/// claims are accepted; present claims must be non-negative integer
/// NumericDate values.
pub(crate) fn validate_credential_temporal_claims(
    issuer_payload: &Value,
    resolved_payload: &Value,
    now_unix: u64,
    clock_skew_seconds: u64,
) -> Result<(), SdJwtEnvelopeError> {
    if now_unix == 0 || clock_skew_seconds > MAX_SD_JWT_CLOCK_SKEW_SECONDS {
        return Err(SdJwtEnvelopeError::InvalidVerificationPolicy);
    }
    let issued_at = numeric_date(resolved_payload.get(ISSUED_AT_CLAIM_NAME))?;
    let not_before = numeric_date(issuer_payload.get(NOT_BEFORE_CLAIM_NAME))?;
    let expires_at = numeric_date(issuer_payload.get(EXPIRATION_CLAIM_NAME))?;

    if matches!((not_before, expires_at), (Some(start), Some(end)) if start >= end)
        || matches!((issued_at, expires_at), (Some(start), Some(end)) if start >= end)
    {
        return Err(SdJwtEnvelopeError::InvalidTemporalClaim);
    }

    let latest_accepted_start = now_unix
        .checked_add(clock_skew_seconds)
        .ok_or(SdJwtEnvelopeError::InvalidVerificationPolicy)?;
    let earliest_accepted_end = now_unix.saturating_sub(clock_skew_seconds);

    if not_before.is_some_and(|value| value > latest_accepted_start) {
        return Err(SdJwtEnvelopeError::CredentialNotYetValid);
    }
    if expires_at.is_some_and(|value| value <= earliest_accepted_end) {
        return Err(SdJwtEnvelopeError::CredentialExpired);
    }
    if issued_at.is_some_and(|value| value > latest_accepted_start) {
        return Err(SdJwtEnvelopeError::InvalidTemporalClaim);
    }
    Ok(())
}

fn numeric_date(value: Option<&Value>) -> Result<Option<u64>, SdJwtEnvelopeError> {
    value
        .map(|value| {
            value
                .as_u64()
                .ok_or(SdJwtEnvelopeError::InvalidTemporalClaim)
        })
        .transpose()
}
