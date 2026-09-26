// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use codec_base64url::base64url_to_bytes;
use envelopes_jwk::Jwk;
use envelopes_jwt::jwt::{decode_verify_jwt_signature_only, JwtError};

use identity_presentation_delivery_siop_core::{
    validate_siop_authentication_request, SiopAuthenticationRequest, SiopAuthenticationResponse,
    SiopDeliveryError, SiopIdTokenClaims, MAX_SIOP_REQUEST_LIFETIME_SECONDS, MAX_SIOP_TEXT_BYTES,
};
use reallyme_crypto::operations::constant_time::equal as constant_time_equal;

use crate::subject_binding::verify_subject_binding;
use crate::SiopVerifierError;
use serde::Deserialize;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Maximum compact SIOP ID-token size accepted before any decoding or lookup.
pub const MAX_SIOP_ID_TOKEN_BYTES: usize = 16_384;

/// Maximum encoded protected-header size accepted before base64url decoding.
pub const MAX_SIOP_PROTECTED_HEADER_BYTES: usize = 2_048;

/// Maximum UTF-8 byte length accepted for a JWT key identifier.
pub const MAX_SIOP_KEY_ID_BYTES: usize = 512;

/// Maximum number of audience values accepted in an ID token.
pub const MAX_SIOP_AUDIENCES: usize = 16;

const SIOP_NONCE_BASE64URL_BYTES: usize = 43;

#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
struct JwtProtectedHeader {
    kid: Option<String>,
}

/// Verified SIOP ID token output.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct VerifiedSiopIdToken {
    /// Decoded SIOP claims that passed signature, subject binding, audience,
    /// nonce, and time checks.
    pub claims: SiopIdTokenClaims,

    /// Optional key identifier from the JWT protected header.
    pub kid: Option<String>,
}

impl core::fmt::Debug for VerifiedSiopIdToken {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("VerifiedSiopIdToken")
            .field("contents", &"<redacted>")
            .finish()
    }
}

/// Resolve a JWT `kid` (from protected header b64) to a public key and JWK.
///
/// Returns `(jwk, public_key_bytes)`.
pub trait SiopKeyResolver {
    /// Return the verification key material for an optional JWT key identifier.
    fn resolve(&self, kid: Option<&str>) -> Option<(Jwk, Vec<u8>)>;
}

fn extract_kid(jwt: &str) -> Result<Option<String>, SiopVerifierError> {
    let (header_b64, _, _) = compact_jwt_parts(jwt)?;
    if header_b64.len() > MAX_SIOP_PROTECTED_HEADER_BYTES {
        return Err(SiopVerifierError::InvalidInput);
    }

    let header_bytes = Zeroizing::new(
        base64url_to_bytes(header_b64).map_err(|_| SiopVerifierError::InvalidInput)?,
    );
    let mut header: JwtProtectedHeader =
        serde_json::from_slice(&header_bytes).map_err(|_| SiopVerifierError::InvalidInput)?;
    if header
        .kid
        .as_ref()
        .is_some_and(|kid| kid.is_empty() || kid.len() > MAX_SIOP_KEY_ID_BYTES)
    {
        return Err(SiopVerifierError::InvalidInput);
    }

    Ok(core::mem::take(&mut header.kid))
}

fn compact_jwt_parts(jwt: &str) -> Result<(&str, &str, &str), SiopVerifierError> {
    if jwt.is_empty() || jwt.len() > MAX_SIOP_ID_TOKEN_BYTES {
        return Err(SiopVerifierError::InvalidInput);
    }

    let mut parts = jwt.split('.');
    let header = parts.next().ok_or(SiopVerifierError::InvalidInput)?;
    let payload = parts.next().ok_or(SiopVerifierError::InvalidInput)?;
    let signature = parts.next().ok_or(SiopVerifierError::InvalidInput)?;
    if header.is_empty() || payload.is_empty() || signature.is_empty() || parts.next().is_some() {
        return Err(SiopVerifierError::InvalidInput);
    }

    Ok((header, payload, signature))
}

fn validate_claims(
    claims: &SiopIdTokenClaims,
    expected_audience: &str,
    expected_nonce_b64url: &str,
    now_unix: i64,
) -> Result<(), SiopVerifierError> {
    if expected_audience.is_empty()
        || expected_audience.len() > MAX_SIOP_TEXT_BYTES
        || expected_nonce_b64url.len() != SIOP_NONCE_BASE64URL_BYTES
        || claims.iss.is_empty()
        || claims.iss.len() > MAX_SIOP_TEXT_BYTES
        || claims.sub.is_empty()
        || claims.sub.len() > MAX_SIOP_TEXT_BYTES
        || claims.nonce.len() != SIOP_NONCE_BASE64URL_BYTES
        || claims.aud.is_empty()
        || claims.aud.len() > MAX_SIOP_AUDIENCES
    {
        return Err(SiopVerifierError::InvalidInput);
    }

    for (index, audience) in claims.aud.iter().enumerate() {
        if audience.is_empty()
            || audience.len() > MAX_SIOP_TEXT_BYTES
            || claims.aud[..index]
                .iter()
                .any(|existing| existing == audience)
        {
            return Err(SiopVerifierError::InvalidInput);
        }
    }

    if !claims
        .aud
        .iter()
        .any(|audience| audience == expected_audience)
    {
        return Err(SiopVerifierError::AudienceMismatch);
    }
    if claims.nonce != expected_nonce_b64url {
        return Err(SiopVerifierError::NonceMismatch);
    }
    if claims.iat > now_unix || claims.exp <= claims.iat {
        return Err(SiopVerifierError::InvalidInput);
    }

    let lifetime = claims
        .exp
        .checked_sub(claims.iat)
        .ok_or(SiopVerifierError::InvalidInput)?;
    let maximum_lifetime = i64::try_from(MAX_SIOP_REQUEST_LIFETIME_SECONDS)
        .map_err(|_| SiopVerifierError::InvalidInput)?;
    if lifetime > maximum_lifetime {
        return Err(SiopVerifierError::InvalidInput);
    }
    if now_unix >= claims.exp {
        return Err(SiopVerifierError::Expired);
    }

    Ok(())
}

fn map_jwt_err(e: JwtError) -> SiopVerifierError {
    match e {
        JwtError::InvalidSignature => SiopVerifierError::InvalidSignature,
        JwtError::InvalidJwtFormat => SiopVerifierError::InvalidInput,
        JwtError::Serialization => SiopVerifierError::InvalidInput,
        JwtError::UnsupportedAlgorithm => SiopVerifierError::InvalidInput,
        _ => SiopVerifierError::InvalidInput,
    }
}

/// Verify a compact JWT SIOP ID token against expected audience and nonce.
///
/// Besides the signature, audience, nonce, and lifetime, this enforces the
/// SIOPv2 self-issued subject binding: `iss` must equal `sub`, and the
/// verifying key must be the subject's key (JWK thumbprint of `sub_jwk`, or a
/// `kid` that is a verification method of the DID in `sub`).
///
/// `expected_audience` must be the relying party's `client_id`. This function
/// does not track nonce use; see [`verify_siop_authentication_response`].
pub fn verify_siop_id_token_jwt(
    id_token_jwt: &str,
    resolver: &dyn SiopKeyResolver,
    expected_audience: &str,
    expected_nonce_b64url: &str,
    now_unix: i64,
) -> Result<VerifiedSiopIdToken, SiopVerifierError> {
    compact_jwt_parts(id_token_jwt)?;
    let kid = extract_kid(id_token_jwt)?;
    let (jwk, public_key) = resolver
        .resolve(kid.as_deref())
        .ok_or(SiopVerifierError::InvalidInput)?;

    let claims: SiopIdTokenClaims =
        decode_verify_jwt_signature_only(id_token_jwt, &jwk, &public_key).map_err(map_jwt_err)?;

    validate_claims(&claims, expected_audience, expected_nonce_b64url, now_unix)?;
    verify_subject_binding(&claims, kid.as_deref(), &jwk)?;

    Ok(VerifiedSiopIdToken { claims, kid })
}

/// Verify a SIOP ID token against the originating request.
///
/// The request is revalidated at `now_unix`, the ID token audience must
/// contain the request `client_id` (SIOPv2 §11.1), and the nonce must equal
/// the request nonce.
///
/// Replay: the request nonce is single-use. After this function succeeds the
/// caller must atomically mark the request (and its nonce) as consumed in its
/// session store and reject any later response for the same request; this
/// stateless verifier cannot do that on the caller's behalf.
pub fn verify_siop_authentication_response(
    req: &SiopAuthenticationRequest,
    resp_id_token_jwt: &str,
    resolver: &dyn SiopKeyResolver,
    now_unix: u64,
) -> Result<VerifiedSiopIdToken, SiopVerifierError> {
    validate_siop_authentication_request(req, now_unix).map_err(map_request_error)?;
    if now_unix >= req.expires_at {
        return Err(SiopVerifierError::Expired);
    }
    let nonce_b64url = codec_base64url::bytes_to_base64url(&req.nonce);
    let now_unix = i64::try_from(now_unix).map_err(|_| SiopVerifierError::InvalidInput)?;

    verify_siop_id_token_jwt(
        resp_id_token_jwt,
        resolver,
        &req.client_id,
        &nonce_b64url,
        now_unix,
    )
}

/// Verify a complete SIOP authentication response, including `state`.
///
/// `expected_state` is the `state` value the relying party sent with the
/// request, if any. The response must echo it exactly; a response state
/// without an expected state, or the reverse, is rejected. All checks and
/// the single-use nonce obligation of [`verify_siop_authentication_response`]
/// apply.
pub fn verify_siop_authentication_response_with_state(
    req: &SiopAuthenticationRequest,
    response: &SiopAuthenticationResponse,
    expected_state: Option<&str>,
    resolver: &dyn SiopKeyResolver,
    now_unix: u64,
) -> Result<VerifiedSiopIdToken, SiopVerifierError> {
    verify_response_state(response.state.as_deref(), expected_state)?;
    let id_token =
        core::str::from_utf8(&response.id_token).map_err(|_| SiopVerifierError::InvalidInput)?;
    verify_siop_authentication_response(req, id_token, resolver, now_unix)
}

fn verify_response_state(
    received: Option<&str>,
    expected: Option<&str>,
) -> Result<(), SiopVerifierError> {
    match (received, expected) {
        (None, None) => Ok(()),
        (Some(received), Some(expected))
            if !expected.is_empty()
                && expected.len() <= MAX_SIOP_TEXT_BYTES
                && constant_time_equal(received.as_bytes(), expected.as_bytes()) =>
        {
            Ok(())
        }
        _ => Err(SiopVerifierError::StateMismatch),
    }
}

fn map_request_error(error: SiopDeliveryError) -> SiopVerifierError {
    match error {
        SiopDeliveryError::Expired => SiopVerifierError::Expired,
        SiopDeliveryError::InvalidInput => SiopVerifierError::InvalidInput,
    }
}
