// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_codec::base64url::base64url_to_bytes;
use reallyme_crypto::jwk::Jwk;
use reallyme_jose::jwt::{
    decode_verify_jwt_signature_only_with_header_validation, JwtHeaderValidationOptions,
};

use super::compress::decompress_status_bytes;
use super::issue_jwt::validate_claims;
use super::model::{
    TokenStatusListClaims, TokenStatusListError, TokenStatusListInvalidReason,
    VerifiedTokenStatusList, MAX_COMPRESSED_STATUS_BYTES, STATUS_LIST_JWT_TYPE,
};

const ACCEPTED_TYPES: &[&str] = &[STATUS_LIST_JWT_TYPE];

/// Verify, validate, and decompress a compact Token Status List JWT.
pub fn verify_token_status_list_jwt(
    jwt: &str,
    issuer_jwk: &Jwk,
    issuer_public_key: &[u8],
    expected_status_list_uri: &str,
    now_unix: u64,
) -> Result<VerifiedTokenStatusList, TokenStatusListError> {
    let claims: TokenStatusListClaims = decode_verify_jwt_signature_only_with_header_validation(
        jwt,
        issuer_jwk,
        issuer_public_key,
        &JwtHeaderValidationOptions::new(false, false, ACCEPTED_TYPES),
    )
    .map_err(|_| TokenStatusListError::Authentication)?;
    validate_claims(&claims)?;
    if claims.sub != expected_status_list_uri {
        return Err(TokenStatusListError::SubjectMismatch);
    }
    if now_unix < claims.iat {
        return Err(TokenStatusListError::NotYetValid);
    }
    if claims.exp.is_some_and(|expires| now_unix >= expires) {
        return Err(TokenStatusListError::Expired);
    }
    let compressed = base64url_to_bytes(&claims.status_list.lst).map_err(|_| {
        TokenStatusListError::InvalidInput(TokenStatusListInvalidReason::InvalidCompressedList)
    })?;
    if compressed.len() > MAX_COMPRESSED_STATUS_BYTES {
        return Err(TokenStatusListError::InvalidInput(
            TokenStatusListInvalidReason::InvalidCompressedList,
        ));
    }
    let packed_statuses = decompress_status_bytes(&compressed, claims.status_list.bits)?;
    Ok(VerifiedTokenStatusList {
        claims,
        packed_statuses,
    })
}
