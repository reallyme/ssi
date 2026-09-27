// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use codec_base64url::base64url_to_bytes;
use envelopes_jwk::Jwk;
use envelopes_jwt::jwt::{decode_verify_jwt_signature_only, JwtError};

use identity_presentation_delivery_siop_core::{
    validate_siop_authentication_request, SiopAuthenticationRequest, SiopAuthenticationResponse,
    SiopDeliveryError, SiopIdTokenClaims, MAX_SIOP_REQUEST_LIFETIME_SECONDS, MAX_SIOP_TEXT_BYTES,
    MIN_SIOP_STATE_BYTES,
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
    claims: SiopIdTokenClaims,

    /// Optional key identifier from the JWT protected header.
    kid: Option<String>,
}

impl VerifiedSiopIdToken {
    /// Borrow the authenticated and validated ID-token claims.
    #[must_use]
    pub const fn claims(&self) -> &SiopIdTokenClaims {
        &self.claims
    }

    /// Borrow the authenticated protected-header key identifier.
    #[must_use]
    pub fn kid(&self) -> Option<&str> {
        self.kid.as_deref()
    }
}

impl core::fmt::Debug for VerifiedSiopIdToken {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("VerifiedSiopIdToken")
            .field("contents", &"<redacted>")
            .finish()
    }
}

/// Resolve a JWT `kid` to the exact public key authorized for that identifier.
///
/// Implementations must authenticate the key source according to the method
/// named by `kid`. A DID resolver, for example, must return a verification
/// method from an authenticated DID document for the DID in `kid`. Resolvers
/// must not follow untrusted redirects, use ambient fallback keys, or return a
/// different key when an explicit `kid` is unknown. The tuple is
/// `(jwk, public_key_bytes)`.
pub trait SiopKeyResolver {
    /// Return verification key material authorized for the exact identifier.
    fn resolve(&self, kid: Option<&str>) -> Option<(Jwk, Vec<u8>)>;

    /// Confirm that `kid` is in the authenticated DID document's
    /// `authentication` relationship for the exact subject DID.
    fn is_authentication_method(&self, subject_did: &str, kid: &str) -> bool;
}

fn jwk_key_id(jwk: &Jwk) -> Option<&str> {
    match jwk {
        Jwk::Ec(value) => value.kid.as_deref(),
        Jwk::Okp(value) => value.kid.as_deref(),
        Jwk::Akp(value) => value.kid.as_deref(),
    }
}

fn validate_resolved_key(
    protected_kid: Option<&str>,
    jwk: &Jwk,
    public_key: &[u8],
) -> Result<(), SiopVerifierError> {
    if jwk_key_id(jwk) != protected_kid {
        return Err(SiopVerifierError::InvalidInput);
    }
    let jwk_public_key = jwk
        .public_key_bytes()
        .map_err(|_| SiopVerifierError::InvalidInput)?;
    if jwk_public_key.len() != public_key.len()
        || !constant_time_equal(jwk_public_key.as_slice(), public_key)
    {
        return Err(SiopVerifierError::InvalidInput);
    }
    Ok(())
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
            || claims
                .aud
                .get(..index)
                .is_none_or(|preceding| preceding.iter().any(|existing| existing == audience))
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
    if claims.azp.as_ref().is_some_and(|azp| {
        azp.is_empty() || azp.len() > MAX_SIOP_TEXT_BYTES || azp != expected_audience
    }) || (claims.aud.len() > 1 && claims.azp.as_deref() != Some(expected_audience))
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
/// `expected_audience` must be the relying party's `client_id`. This low-level
/// operation does not validate a SIOP response's `state`, bind the token to an
/// originating request, or track nonce use. Protocol handlers should use
/// [`verify_siop_authentication_response`] instead.
fn verify_siop_id_token_jwt(
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
    validate_resolved_key(kid.as_deref(), &jwk, &public_key)?;

    let claims: SiopIdTokenClaims =
        decode_verify_jwt_signature_only(id_token_jwt, &jwk, &public_key).map_err(map_jwt_err)?;

    validate_claims(&claims, expected_audience, expected_nonce_b64url, now_unix)?;
    let did_authentication_authorized = match kid.as_deref() {
        Some(key_id) if claims.sub.starts_with("did:") => {
            resolver.is_authentication_method(&claims.sub, key_id)
        }
        _ => false,
    };
    verify_subject_binding(&claims, kid.as_deref(), &jwk, did_authentication_authorized)?;

    Ok(VerifiedSiopIdToken { claims, kid })
}

/// Verify a complete SIOP response against the originating request and state.
///
/// The request is revalidated at `now_unix`, the ID token audience must
/// contain the request `client_id` (SIOPv2 §11.1), and the nonce must equal
/// the request nonce. The response must echo the request's state exactly.
///
/// Replay: the request nonce is single-use. After this function succeeds the
/// caller must atomically mark the request (and its nonce) as consumed in its
/// session store and reject any later response for the same request; this
/// stateless verifier cannot do that on the caller's behalf.
pub fn verify_siop_authentication_response(
    req: &SiopAuthenticationRequest,
    response: &SiopAuthenticationResponse,
    resolver: &dyn SiopKeyResolver,
    now_unix: u64,
) -> Result<VerifiedSiopIdToken, SiopVerifierError> {
    verify_response_state(response.state.as_str(), req.state.as_str())?;
    let resp_id_token_jwt =
        core::str::from_utf8(&response.id_token).map_err(|_| SiopVerifierError::InvalidInput)?;
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

fn verify_response_state(received: &str, expected: &str) -> Result<(), SiopVerifierError> {
    if expected.len() >= MIN_SIOP_STATE_BYTES
        && expected.len() <= MAX_SIOP_TEXT_BYTES
        && received.len() == expected.len()
        && constant_time_equal(received.as_bytes(), expected.as_bytes())
    {
        Ok(())
    } else {
        Err(SiopVerifierError::StateMismatch)
    }
}

fn map_request_error(error: SiopDeliveryError) -> SiopVerifierError {
    match error {
        SiopDeliveryError::Expired => SiopVerifierError::Expired,
        SiopDeliveryError::InvalidInput => SiopVerifierError::InvalidInput,
    }
}
