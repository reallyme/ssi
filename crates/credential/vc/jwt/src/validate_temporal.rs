// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::{VcJwtError, VcJwtPayload};

/// Maximum clock skew, in seconds, a verifier may tolerate for VC-JWT
/// temporal claims.
pub const MAX_VC_JWT_CLOCK_SKEW_SECONDS: u64 = 300;

/// Verifier policy for VC-JWT temporal claim validation.
///
/// There is no default: callers must supply the current time explicitly so a
/// missing clock can never silently disable expiry checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VcJwtVerificationOptions {
    /// Current verifier time as UTC seconds since the Unix epoch. Zero is
    /// rejected with [`VcJwtError::InvalidVerificationTime`].
    pub now_unix: u64,

    /// Tolerated clock skew in seconds, applied to `exp`, `nbf`, and `iat`.
    /// Values above [`MAX_VC_JWT_CLOCK_SKEW_SECONDS`] are rejected with
    /// [`VcJwtError::InvalidVerificationTime`].
    pub clock_skew_seconds: u64,
}

/// Reject verification options that would disable or distort time checks.
pub(crate) fn validate_verification_options(
    options: &VcJwtVerificationOptions,
) -> Result<(), VcJwtError> {
    if options.now_unix == 0 || options.clock_skew_seconds > MAX_VC_JWT_CLOCK_SKEW_SECONDS {
        return Err(VcJwtError::InvalidVerificationTime);
    }
    Ok(())
}

/// Validate `exp`, `nbf`, and `iat` against the verifier's current time.
///
/// Each claim is optional, but when present it must be a non-negative
/// NumericDate, `exp` must follow `nbf`, and every claim must satisfy the
/// verification window widened by the configured clock skew.
pub(crate) fn validate_vc_jwt_temporal_claims(
    payload: &VcJwtPayload,
    options: &VcJwtVerificationOptions,
) -> Result<(), VcJwtError> {
    validate_verification_options(options)?;

    let expires = numeric_date(payload.exp)?;
    let not_before = numeric_date(payload.nbf)?;
    let issued_at = numeric_date(payload.iat)?;

    if let (Some(not_before), Some(expires)) = (not_before, expires) {
        if expires <= not_before {
            return Err(VcJwtError::InvalidTemporalClaim);
        }
    }

    let earliest_accepted_expiry = options.now_unix.saturating_sub(options.clock_skew_seconds);
    let latest_accepted_start = options
        .now_unix
        .checked_add(options.clock_skew_seconds)
        .ok_or(VcJwtError::InvalidVerificationTime)?;

    if expires.is_some_and(|expires| expires <= earliest_accepted_expiry) {
        return Err(VcJwtError::CredentialExpired);
    }
    if not_before.is_some_and(|not_before| not_before > latest_accepted_start) {
        return Err(VcJwtError::CredentialNotYetValid);
    }
    if issued_at.is_some_and(|issued_at| issued_at > latest_accepted_start) {
        return Err(VcJwtError::InvalidTemporalClaim);
    }

    Ok(())
}

fn numeric_date(value: Option<i64>) -> Result<Option<u64>, VcJwtError> {
    value
        .map(|seconds| u64::try_from(seconds).map_err(|_| VcJwtError::InvalidTemporalClaim))
        .transpose()
}
