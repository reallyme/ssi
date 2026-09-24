// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Compact JWT helpers with injected signing and verification.

use core::fmt;

use reallyme_codec::base64url::{base64url_to_bytes, bytes_to_base64url};
use serde::de::DeserializeOwned;
use serde::Serialize;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::error::{OauthError, OauthResult, Reason};
use crate::strict_json::validate_strict_json;
use crate::validation::{validate_compact_jwt, MAX_COMPACT_JWT_BYTES};

/// Compact JWT value.
#[derive(PartialEq, Eq)]
pub struct CompactJwt {
    value: String,
}

impl fmt::Debug for CompactJwt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CompactJwt([REDACTED])")
    }
}

impl Zeroize for CompactJwt {
    fn zeroize(&mut self) {
        self.value.zeroize();
    }
}

impl Drop for CompactJwt {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for CompactJwt {}

impl CompactJwt {
    /// Creates a compact JWT after shape validation.
    pub fn new(value: String) -> OauthResult<Self> {
        validate_compact_jwt(&value)?;
        Ok(Self { value })
    }

    /// Returns the JWT string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.value
    }

    /// Splits the compact JWT into signing input and signature.
    pub fn signing_parts(&self) -> OauthResult<(&str, &str)> {
        let first = self
            .value
            .find('.')
            .ok_or(OauthError::new(Reason::InvalidJson))?;
        let second_offset = self.value[first + 1..]
            .find('.')
            .ok_or(OauthError::new(Reason::InvalidJson))?;
        let second = first
            .checked_add(1)
            .and_then(|value| value.checked_add(second_offset))
            .ok_or(OauthError::new(Reason::InvalidJson))?;
        Ok((&self.value[..second], &self.value[second + 1..]))
    }
}

/// Asymmetric JWT signer injected by holder or adapter code.
pub trait JwtSigner {
    /// JOSE `alg` value used by the signer.
    fn algorithm(&self) -> &str;

    /// Signs the compact JWT signing input.
    fn sign(&self, signing_input: &[u8]) -> OauthResult<Vec<u8>>;
}

/// Compact JWT verifier injected by issuer or adapter code.
pub trait JwtVerifier {
    /// Verifies the compact JWT signature against the supplied protected header.
    fn verify(
        &self,
        protected_header: &serde_json::Value,
        signing_input: &[u8],
        signature: &[u8],
    ) -> OauthResult<()>;
}

/// Builds a compact JWS from a typed header and payload.
pub fn sign_compact_jwt<H, P>(
    header: &H,
    payload: &P,
    signer: &dyn JwtSigner,
) -> OauthResult<CompactJwt>
where
    H: Serialize,
    P: Serialize,
{
    let header_json = Zeroizing::new(
        serde_json::to_vec(header).map_err(|_| OauthError::new(Reason::InvalidJson))?,
    );
    let payload_json = Zeroizing::new(
        serde_json::to_vec(payload).map_err(|_| OauthError::new(Reason::InvalidJson))?,
    );
    let header_part = Zeroizing::new(bytes_to_base64url(&header_json));
    let payload_part = Zeroizing::new(bytes_to_base64url(&payload_json));
    let signing_length = header_part
        .len()
        .checked_add(1)
        .and_then(|length| length.checked_add(payload_part.len()))
        .ok_or(OauthError::new(Reason::InvalidString))?;
    if signing_length >= MAX_COMPACT_JWT_BYTES {
        return Err(OauthError::new(Reason::InvalidString));
    }
    let mut signing_input = Zeroizing::new(String::with_capacity(signing_length));
    signing_input.push_str(&header_part);
    signing_input.push('.');
    signing_input.push_str(&payload_part);
    let signature = signer
        .sign(signing_input.as_bytes())
        .map_err(|_| OauthError::new(Reason::SigningFailed))?;
    let signature_part = Zeroizing::new(bytes_to_base64url(&signature));
    let compact_length = signing_input
        .len()
        .checked_add(1)
        .and_then(|length| length.checked_add(signature_part.len()))
        .ok_or(OauthError::new(Reason::InvalidString))?;
    if compact_length > MAX_COMPACT_JWT_BYTES {
        return Err(OauthError::new(Reason::InvalidString));
    }
    let mut compact = String::with_capacity(compact_length);
    compact.push_str(&signing_input);
    compact.push('.');
    compact.push_str(&signature_part);
    CompactJwt::new(compact)
}

/// Decodes a compact JWT header and payload.
pub fn decode_compact_jwt<H, P>(jwt: &CompactJwt) -> OauthResult<(H, P, Vec<u8>)>
where
    H: DeserializeOwned,
    P: DeserializeOwned,
{
    let mut parts = jwt.as_str().split('.');
    let encoded_header = parts.next().ok_or(OauthError::new(Reason::InvalidJson))?;
    let encoded_payload = parts.next().ok_or(OauthError::new(Reason::InvalidJson))?;
    let encoded_signature = parts.next().ok_or(OauthError::new(Reason::InvalidJson))?;
    if parts.next().is_some() {
        return Err(OauthError::new(Reason::InvalidJson));
    }
    let header_bytes = Zeroizing::new(decode_base64url_component(encoded_header)?);
    let payload_bytes = Zeroizing::new(decode_base64url_component(encoded_payload)?);
    let signature = decode_base64url_component(encoded_signature)?;
    validate_strict_json(&header_bytes)?;
    validate_strict_json(&payload_bytes)?;
    let header =
        serde_json::from_slice(&header_bytes).map_err(|_| OauthError::new(Reason::InvalidJson))?;
    let payload =
        serde_json::from_slice(&payload_bytes).map_err(|_| OauthError::new(Reason::InvalidJson))?;
    Ok((header, payload, signature))
}

fn decode_base64url_component(encoded: &str) -> OauthResult<Vec<u8>> {
    let decoded = base64url_to_bytes(encoded).map_err(|_| OauthError::new(Reason::InvalidJson))?;
    // RFC 7515 §2 uses the URL-safe alphabet without padding. Decode-and-
    // re-encode prevents multiple wire representations from identifying the
    // same signed bytes in caches, replay stores, or audit receipts.
    if bytes_to_base64url(&decoded) != encoded {
        return Err(OauthError::new(Reason::InvalidJson));
    }
    Ok(decoded)
}
