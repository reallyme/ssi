// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_crypto::jwk::Jwk;
use reallyme_jose::jwt::{
    decode_verify_jwt_signature_only_with_header_validation, JwtHeaderValidationOptions,
};

use super::check_freshness::check_freshness;
use super::issue_jwt::validate_claims;
use super::model::{
    TokenStatusListClaims, TokenStatusListError, TokenStatusListFreshnessPolicy,
    VerifiedTokenStatusList, STATUS_LIST_JWT_TYPE,
};

const ACCEPTED_TYPES: &[&str] = &[STATUS_LIST_JWT_TYPE];

/// Verify, validate, and decompress a compact Token Status List JWT.
///
/// `freshness` bounds how long after `iat` the list is accepted, honoring a
/// shorter `ttl` claim; see [`TokenStatusListFreshnessPolicy`].
pub fn verify_token_status_list_jwt(
    jwt: &str,
    issuer_jwk: &Jwk,
    issuer_public_key: &[u8],
    expected_status_list_uri: &str,
    now_unix: u64,
    freshness: TokenStatusListFreshnessPolicy,
) -> Result<VerifiedTokenStatusList, TokenStatusListError> {
    let claims: TokenStatusListClaims = decode_verify_jwt_signature_only_with_header_validation(
        jwt,
        issuer_jwk,
        issuer_public_key,
        &JwtHeaderValidationOptions::new(false, false, ACCEPTED_TYPES),
    )
    .map_err(|_| TokenStatusListError::Authentication)?;
    let decoded = validate_claims(&claims)?;
    if claims.sub != expected_status_list_uri {
        return Err(TokenStatusListError::SubjectMismatch);
    }
    check_freshness(&claims, now_unix, freshness)?;
    Ok(VerifiedTokenStatusList {
        claims,
        packed_statuses: decoded.packed,
    })
}
