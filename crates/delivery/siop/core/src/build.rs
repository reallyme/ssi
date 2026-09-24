// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::{SiopAuthenticationRequest, SiopDeliveryError};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Exact nonce length required for SIOP replay binding.
pub const SIOP_NONCE_BYTES: usize = 32;

/// Maximum UTF-8 bytes accepted for one SIOP identifier or mode.
pub const MAX_SIOP_TEXT_BYTES: usize = 2048;

/// Maximum number of scopes accepted in one request.
pub const MAX_SIOP_SCOPES: usize = 32;

/// Maximum UTF-8 bytes accepted for one scope token.
pub const MAX_SIOP_SCOPE_BYTES: usize = 256;

/// Maximum lifetime accepted for a locally constructed request.
pub const MAX_SIOP_REQUEST_LIFETIME_SECONDS: u64 = 3600;

/// Inputs required to construct a SIOP v2 authentication request.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct BuildSiopAuthenticationRequestInput {
    /// Relying party client identifier.
    pub client_id: String,

    /// Strong challenge nonce bytes; this implementation requires 32 bytes.
    pub nonce: Vec<u8>,

    /// Audience expected in the resulting SIOP ID token.
    pub audience: String,

    /// Response mode requested by the relying party.
    pub response_mode: String,

    /// Requested OAuth/OIDC scopes.
    pub scope: Vec<String>,

    /// Request creation time in Unix seconds.
    pub now_unix: u64,

    /// Request lifetime in seconds.
    pub ttl_secs: u64,
}

impl core::fmt::Debug for BuildSiopAuthenticationRequestInput {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("BuildSiopAuthenticationRequestInput")
            .field("contents", &"<redacted>")
            .finish()
    }
}

/// Build a SIOP authentication request with deterministic lifetime checks.
pub fn build_siop_authentication_request(
    mut input: BuildSiopAuthenticationRequestInput,
) -> Result<SiopAuthenticationRequest, SiopDeliveryError> {
    validate_request_fields(
        input.client_id.as_str(),
        input.nonce.as_slice(),
        input.audience.as_str(),
        input.response_mode.as_str(),
        input.scope.as_slice(),
    )?;
    if input.ttl_secs == 0 || input.ttl_secs > MAX_SIOP_REQUEST_LIFETIME_SECONDS {
        return Err(SiopDeliveryError::InvalidInput);
    }

    let expires_at = input
        .now_unix
        .checked_add(input.ttl_secs)
        .ok_or(SiopDeliveryError::InvalidInput)?;

    Ok(SiopAuthenticationRequest {
        client_id: core::mem::take(&mut input.client_id),
        nonce: core::mem::take(&mut input.nonce),
        audience: core::mem::take(&mut input.audience),
        response_mode: core::mem::take(&mut input.response_mode),
        scope: core::mem::take(&mut input.scope),
        created_at: input.now_unix,
        expires_at,
    })
}

/// Validate required SIOP request fields and expiration at a given time.
pub fn validate_siop_authentication_request(
    req: &SiopAuthenticationRequest,
    now_unix: u64,
) -> Result<(), SiopDeliveryError> {
    validate_request_fields(
        req.client_id.as_str(),
        req.nonce.as_slice(),
        req.audience.as_str(),
        req.response_mode.as_str(),
        req.scope.as_slice(),
    )?;

    let lifetime = req
        .expires_at
        .checked_sub(req.created_at)
        .ok_or(SiopDeliveryError::InvalidInput)?;
    if lifetime == 0 || lifetime > MAX_SIOP_REQUEST_LIFETIME_SECONDS {
        return Err(SiopDeliveryError::InvalidInput);
    }
    if now_unix > req.expires_at {
        return Err(SiopDeliveryError::Expired);
    }
    if req.created_at > now_unix {
        return Err(SiopDeliveryError::InvalidInput);
    }

    Ok(())
}

fn validate_request_fields(
    client_id: &str,
    nonce: &[u8],
    audience: &str,
    response_mode: &str,
    scopes: &[String],
) -> Result<(), SiopDeliveryError> {
    if client_id.is_empty()
        || client_id.len() > MAX_SIOP_TEXT_BYTES
        || audience.is_empty()
        || audience.len() > MAX_SIOP_TEXT_BYTES
        || response_mode.is_empty()
        || response_mode.len() > MAX_SIOP_TEXT_BYTES
        || nonce.len() != SIOP_NONCE_BYTES
        || scopes.is_empty()
        || scopes.len() > MAX_SIOP_SCOPES
    {
        return Err(SiopDeliveryError::InvalidInput);
    }

    for (index, scope) in scopes.iter().enumerate() {
        if scope.is_empty() || scope.len() > MAX_SIOP_SCOPE_BYTES {
            return Err(SiopDeliveryError::InvalidInput);
        }
        if scopes[..index].iter().any(|existing| existing == scope) {
            return Err(SiopDeliveryError::InvalidInput);
        }
    }

    Ok(())
}
