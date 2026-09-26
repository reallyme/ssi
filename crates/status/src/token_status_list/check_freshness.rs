// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::model::{
    TokenStatusListClaims, TokenStatusListError, TokenStatusListFreshnessPolicy,
    TokenStatusListInvalidReason,
};

/// Enforce `iat`, `exp`, and the relying-party freshness ceiling.
///
/// A list is stale once `now >= iat + min(policy.max_age_secs, ttl)`.
pub(crate) fn check_freshness(
    claims: &TokenStatusListClaims,
    now_unix: u64,
    policy: TokenStatusListFreshnessPolicy,
) -> Result<(), TokenStatusListError> {
    if now_unix < claims.iat {
        return Err(TokenStatusListError::NotYetValid);
    }
    if claims.exp.is_some_and(|expires| now_unix >= expires) {
        return Err(TokenStatusListError::Expired);
    }
    if policy.max_age_secs == 0 {
        return Err(TokenStatusListError::InvalidInput(
            TokenStatusListInvalidReason::InvalidTimeClaims,
        ));
    }
    let window = claims
        .ttl
        .map_or(policy.max_age_secs, |ttl| ttl.min(policy.max_age_secs));
    let stale_at = claims
        .iat
        .checked_add(window)
        .ok_or(TokenStatusListError::InvalidInput(
            TokenStatusListInvalidReason::InvalidTimeClaims,
        ))?;
    if now_unix >= stale_at {
        return Err(TokenStatusListError::Expired);
    }
    Ok(())
}
