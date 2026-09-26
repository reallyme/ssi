// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Shared OAuth validation helpers.

use std::net::{Ipv4Addr, Ipv6Addr};

use url::{Host, Url};

use crate::error::{OauthError, OauthResult, Reason};

/// Maximum OAuth JSON body accepted by substrate parsers.
pub const MAX_JSON_BYTES: usize = 64 * 1024;

/// Maximum compact JWT accepted from untrusted headers (DPoP proofs, wallet
/// attestation, PoP). Bounds base64 decode and serde work before a verifier
/// sees attacker-controlled input.
pub const MAX_COMPACT_JWT_BYTES: usize = 16 * 1024;
/// Maximum size for a non-JWT OAuth string accepted at public boundaries.
pub const MAX_TOKEN_BYTES: usize = 16 * 1024;

/// JOSE `alg` values accepted for sender-constraining and client-authentication
/// proofs. RFC 9449 §4.2 and the attestation-based client-auth draft require a
/// registered asymmetric signature algorithm; `none` and symmetric MAC
/// algorithms are rejected.
const ACCEPTED_ASYMMETRIC_JOSE_ALGS: &[&str] = &[
    "ES256", "ES384", "ES512", "ES256K", "EdDSA", "PS256", "PS384", "PS512", "RS256", "RS384",
    "RS512",
];

/// Validates a non-empty protocol string.
pub fn validate_token(value: &str) -> OauthResult<()> {
    if value.len() > MAX_TOKEN_BYTES
        || value.trim().is_empty()
        || value.chars().any(char::is_control)
    {
        return Err(OauthError::new(Reason::InvalidString));
    }
    Ok(())
}

/// Validates that a JOSE `alg` is a supported asymmetric signature algorithm.
pub fn validate_asymmetric_jose_alg(alg: &str) -> OauthResult<()> {
    if ACCEPTED_ASYMMETRIC_JOSE_ALGS.contains(&alg) {
        Ok(())
    } else {
        Err(OauthError::new(Reason::InvalidString))
    }
}

/// Validates a compact JWT shape without parsing claims.
pub fn validate_compact_jwt(value: &str) -> OauthResult<()> {
    validate_token(value)?;
    if value.len() > MAX_COMPACT_JWT_BYTES {
        return Err(OauthError::new(Reason::InvalidString));
    }
    let mut parts = value.split('.');
    let header = parts.next();
    let payload = parts.next();
    let signature = parts.next();
    let extra = parts.next();
    match (header, payload, signature, extra) {
        (Some(h), Some(p), Some(s), None) if !h.is_empty() && !p.is_empty() && !s.is_empty() => {
            Ok(())
        }
        _ => Err(OauthError::new(Reason::InvalidString)),
    }
}

/// Validates an HTTPS URL. Loopback HTTP is only for explicit local adapters.
///
/// URLs carrying userinfo (`user:password@`) are rejected: OAuth metadata,
/// endpoint, and issuer URLs never legitimately embed credentials, and
/// userinfo is a common vector for host confusion.
pub fn validate_https_url(value: &str, allow_loopback_http: bool) -> OauthResult<()> {
    validate_token(value)?;
    let url = Url::parse(value).map_err(|_| OauthError::new(Reason::InvalidUrl))?;
    if !url.username().is_empty() || url.password().is_some() || url.host().is_none() {
        return Err(OauthError::new(Reason::InvalidUrl));
    }
    match url.scheme() {
        "https" => Ok(()),
        "http" if allow_loopback_http && is_loopback(&url) => Ok(()),
        _ => Err(OauthError::new(Reason::InvalidUrl)),
    }
}

/// Validates an RFC 8414 issuer identifier.
pub fn validate_issuer_identifier(value: &str) -> OauthResult<()> {
    validate_https_url(value, false)?;
    let url = Url::parse(value).map_err(|_| OauthError::new(Reason::InvalidUrl))?;
    if url.query().is_some() || url.fragment().is_some() {
        return Err(OauthError::new(Reason::InvalidUrl));
    }
    Ok(())
}

/// Validates optional string list metadata.
pub fn validate_optional_string_list(values: &Option<Vec<String>>) -> OauthResult<()> {
    if let Some(items) = values {
        if items.is_empty() {
            return Err(OauthError::new(Reason::MissingRequiredValue));
        }
        for item in items {
            validate_token(item)?;
        }
    }
    Ok(())
}

/// Validates an optional HTTPS URL.
pub fn validate_optional_https_url(value: &Option<String>) -> OauthResult<()> {
    if let Some(url) = value {
        validate_https_url(url, false)?;
    }
    Ok(())
}

/// Normalizes an HTTP target URI for RFC 9449 `htu` comparison.
pub fn normalize_uri_without_query_or_fragment(value: &str) -> OauthResult<String> {
    validate_https_url(value, false)?;
    let mut url = Url::parse(value).map_err(|_| OauthError::new(Reason::InvalidUrl))?;
    url.set_query(None);
    url.set_fragment(None);
    if let Some(host) = url.host_str() {
        let normalized_host = host.to_ascii_lowercase();
        url.set_host(Some(&normalized_host))
            .map_err(|_| OauthError::new(Reason::InvalidUrl))?;
    }
    Ok(url.to_string())
}

fn is_loopback(url: &Url) -> bool {
    match url.host() {
        Some(Host::Domain(domain)) => domain.eq_ignore_ascii_case("localhost"),
        Some(Host::Ipv4(address)) => address == Ipv4Addr::LOCALHOST,
        Some(Host::Ipv6(address)) => address == Ipv6Addr::LOCALHOST,
        None => false,
    }
}
