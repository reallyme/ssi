// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::claims::numeric_date;
use crate::{JwtVcEnvelopeError, JwtVcPayload, JwtVcVerificationOptions};

/// Maximum clock skew, in seconds, a verifier may tolerate for JWT-VC
/// temporal claims.
pub const MAX_JWT_VC_CLOCK_SKEW_SECONDS: u64 = 300;

/// Reject verification options that would disable or distort time checks.
pub(crate) fn validate_verification_options(
    options: &JwtVcVerificationOptions,
) -> Result<(), JwtVcEnvelopeError> {
    if options.now_unix == 0 || options.clock_skew_seconds > MAX_JWT_VC_CLOCK_SKEW_SECONDS {
        return Err(JwtVcEnvelopeError::InvalidVerificationTime);
    }
    Ok(())
}

/// Validate `exp`, `nbf`, and `iat` against the verifier's current time.
///
/// Each claim is optional, but when present it must be a non-negative
/// NumericDate and must satisfy the verification window widened by the
/// configured clock skew.
pub(crate) fn validate_jwt_vc_temporal_claims(
    payload: &JwtVcPayload,
    options: &JwtVcVerificationOptions,
) -> Result<(), JwtVcEnvelopeError> {
    validate_verification_options(options)?;

    let expires = numeric_date(payload.exp)?;
    let not_before = numeric_date(payload.nbf)?;
    let issued_at = numeric_date(payload.iat)?;

    let earliest_accepted_expiry = options.now_unix.saturating_sub(options.clock_skew_seconds);
    let latest_accepted_start = options
        .now_unix
        .checked_add(options.clock_skew_seconds)
        .ok_or(JwtVcEnvelopeError::InvalidVerificationTime)?;

    if expires.is_some_and(|expires| expires <= earliest_accepted_expiry) {
        return Err(JwtVcEnvelopeError::CredentialExpired);
    }
    if not_before.is_some_and(|not_before| not_before > latest_accepted_start) {
        return Err(JwtVcEnvelopeError::CredentialNotYetValid);
    }
    if issued_at.is_some_and(|issued_at| issued_at > latest_accepted_start) {
        return Err(JwtVcEnvelopeError::InvalidTemporalClaim);
    }

    Ok(())
}
