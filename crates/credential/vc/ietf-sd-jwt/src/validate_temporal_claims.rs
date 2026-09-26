// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Verification-time validation of SD-JWT VC temporal claims.

use serde_json::Value;

use crate::error::IetfSdJwtVcError;

/// Maximum symmetric clock skew accepted for `exp`, `nbf`, and future `iat`.
pub const MAX_IETF_SD_JWT_CLOCK_SKEW_SECONDS: u64 = 300;

/// Default symmetric clock skew applied by [`IetfSdJwtTemporalPolicy::new`].
pub const DEFAULT_IETF_SD_JWT_CLOCK_SKEW_SECONDS: u64 = 60;

/// Verifier clock used to validate credential `exp`, `nbf`, and `iat`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IetfSdJwtTemporalPolicy {
    /// Verifier clock as Unix seconds. Zero is rejected so an unset clock can
    /// never disable temporal validation.
    pub now_unix: u64,
    /// Symmetric leeway, bounded by [`MAX_IETF_SD_JWT_CLOCK_SKEW_SECONDS`].
    pub clock_skew_seconds: u64,
}

impl IetfSdJwtTemporalPolicy {
    /// Construct a policy evaluated at `now_unix` with the default skew.
    #[must_use]
    pub const fn new(now_unix: u64) -> Self {
        Self {
            now_unix,
            clock_skew_seconds: DEFAULT_IETF_SD_JWT_CLOCK_SKEW_SECONDS,
        }
    }

    pub(crate) fn validate(&self) -> Result<(), IetfSdJwtVcError> {
        if self.now_unix == 0 || self.clock_skew_seconds > MAX_IETF_SD_JWT_CLOCK_SKEW_SECONDS {
            return Err(IetfSdJwtVcError::InvalidVerificationPolicy);
        }
        Ok(())
    }
}

/// Validate the credential validity window against the verifier's clock.
///
/// `exp` and `nbf` are read from the issuer-signed payload because they are
/// never selectively disclosable. `iat` may be selectively disclosed, so it is
/// read from the authenticated resolved payload. Absent claims are accepted;
/// present claims must be non-negative integer NumericDate values.
pub(crate) fn validate_credential_temporal_claims(
    issuer_payload: &Value,
    resolved_payload: &Value,
    policy: &IetfSdJwtTemporalPolicy,
) -> Result<(), IetfSdJwtVcError> {
    policy.validate()?;
    let issued_at = numeric_date(resolved_payload.get("iat"))?;
    let not_before = numeric_date(issuer_payload.get("nbf"))?;
    let expires_at = numeric_date(issuer_payload.get("exp"))?;

    if matches!((not_before, expires_at), (Some(start), Some(end)) if start >= end)
        || matches!((issued_at, expires_at), (Some(start), Some(end)) if start >= end)
    {
        return Err(IetfSdJwtVcError::InvalidTemporalClaim);
    }

    let latest_accepted_start = policy
        .now_unix
        .checked_add(policy.clock_skew_seconds)
        .ok_or(IetfSdJwtVcError::InvalidVerificationPolicy)?;
    let earliest_accepted_end = policy.now_unix.saturating_sub(policy.clock_skew_seconds);

    if not_before.is_some_and(|value| value > latest_accepted_start) {
        return Err(IetfSdJwtVcError::CredentialNotYetValid);
    }
    if expires_at.is_some_and(|value| value <= earliest_accepted_end) {
        return Err(IetfSdJwtVcError::CredentialExpired);
    }
    if issued_at.is_some_and(|value| value > latest_accepted_start) {
        return Err(IetfSdJwtVcError::InvalidTemporalClaim);
    }
    Ok(())
}

fn numeric_date(value: Option<&Value>) -> Result<Option<u64>, IetfSdJwtVcError> {
    value
        .map(|value| value.as_u64().ok_or(IetfSdJwtVcError::InvalidTemporalClaim))
        .transpose()
}
