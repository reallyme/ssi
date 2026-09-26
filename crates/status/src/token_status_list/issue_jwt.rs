// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#[cfg(any(feature = "native", feature = "wasm"))]
use reallyme_crypto::jwk::Jwk;
#[cfg(any(feature = "native", feature = "wasm"))]
use reallyme_crypto::signer::Signer;
#[cfg(any(feature = "native", feature = "wasm"))]
use reallyme_jose::jwt::{
    encode_signed_jwt_with_header_options, encode_signed_jwt_with_signer_and_header_options,
    JwtHeaderEncodeOptions,
};

use super::compress::decompress_status_bytes;
use super::model::{
    TokenStatusListClaims, TokenStatusListError, TokenStatusListInvalidReason,
    MAX_STATUS_URI_BYTES, STATUS_LIST_JWT_TYPE,
};

/// Status bytes decoded once during claim validation.
pub(crate) struct DecodedStatusList {
    /// ZLIB-compressed status bytes as carried by the token.
    pub(crate) compressed: Vec<u8>,
    /// Decompressed packed status bytes.
    pub(crate) packed: Vec<u8>,
}

/// Validate claims and return the decoded status list so callers never
/// decompress the same list twice.
pub(crate) fn validate_claims(
    claims: &TokenStatusListClaims,
) -> Result<DecodedStatusList, TokenStatusListError> {
    let compressed = reallyme_codec::base64url::base64url_to_bytes(&claims.status_list.lst)
        .map_err(|_| {
            TokenStatusListError::InvalidInput(TokenStatusListInvalidReason::InvalidCompressedList)
        })?;
    let packed = validate_claims_with_compressed(claims, &compressed)?;
    Ok(DecodedStatusList { compressed, packed })
}

/// Validate claims whose compressed status bytes were already decoded,
/// returning the decompressed packed status bytes.
pub(crate) fn validate_claims_with_compressed(
    claims: &TokenStatusListClaims,
    compressed: &[u8],
) -> Result<Vec<u8>, TokenStatusListError> {
    if !matches!(
        claims.profile,
        super::model::TokenStatusListProfile::IetfDraft21
    ) {
        return Err(TokenStatusListError::InvalidInput(
            TokenStatusListInvalidReason::UnsupportedProfile,
        ));
    }
    validate_uri(&claims.sub)?;
    if let Some(uri) = claims.status_list.aggregation_uri.as_deref() {
        validate_uri(uri)?;
    }
    if !matches!(claims.status_list.bits, 1 | 2 | 4 | 8) {
        return Err(TokenStatusListError::InvalidInput(
            TokenStatusListInvalidReason::InvalidBits,
        ));
    }
    let packed = decompress_status_bytes(compressed, claims.status_list.bits)?;
    if claims.exp.is_some_and(|expires| expires <= claims.iat)
        || claims.ttl.is_some_and(|ttl| ttl == 0)
    {
        return Err(TokenStatusListError::InvalidInput(
            TokenStatusListInvalidReason::InvalidTimeClaims,
        ));
    }
    Ok(packed)
}

fn validate_uri(value: &str) -> Result<(), TokenStatusListError> {
    let valid_length = !value.is_empty() && value.len() <= MAX_STATUS_URI_BYTES;
    let is_absolute = url::Url::parse(value).is_ok();
    if !valid_length || !is_absolute {
        return Err(TokenStatusListError::InvalidInput(
            TokenStatusListInvalidReason::InvalidUri,
        ));
    }
    Ok(())
}

/// Issue a compact-JWS Token Status List JWT with the mandatory `typ` value.
#[cfg(any(feature = "native", feature = "wasm"))]
pub fn issue_token_status_list_jwt(
    claims: &TokenStatusListClaims,
    issuer_jwk: &Jwk,
    issuer_private_key: &[u8],
) -> Result<String, TokenStatusListError> {
    let _validated = validate_claims(claims)?;
    encode_signed_jwt_with_header_options(
        claims,
        issuer_jwk,
        issuer_private_key,
        &JwtHeaderEncodeOptions::new(Some(STATUS_LIST_JWT_TYPE.to_owned())),
    )
    .map_err(|_| TokenStatusListError::Authentication)
}

/// Issue a compact-JWS Token Status List JWT with a provider-owned key.
#[cfg(any(feature = "native", feature = "wasm"))]
pub fn issue_token_status_list_jwt_with_signer(
    claims: &TokenStatusListClaims,
    issuer_jwk: &Jwk,
    signer: &dyn Signer,
) -> Result<String, TokenStatusListError> {
    let _validated = validate_claims(claims)?;
    encode_signed_jwt_with_signer_and_header_options(
        claims,
        issuer_jwk,
        signer,
        &JwtHeaderEncodeOptions::new(Some(STATUS_LIST_JWT_TYPE.to_owned())),
    )
    .map_err(|_| TokenStatusListError::Authentication)
}
