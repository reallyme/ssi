// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Shared OAuth validation helpers.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

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
    // WHATWG URL parsing treats a backslash as a path separator for special
    // schemes. Reject it before parsing so adapters never fetch a different
    // host than a human reading the stored OAuth endpoint would infer.
    if value.as_bytes().contains(&b'\\') {
        return Err(OauthError::new(Reason::InvalidUrl));
    }
    let url = Url::parse(value).map_err(|_| OauthError::new(Reason::InvalidUrl))?;
    if !url.username().is_empty()
        || url.password().is_some()
        || url.host().is_none()
        || url.fragment().is_some()
    {
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
    validate_public_https_url(value)?;
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

/// Validate an HTTPS endpoint whose literal host cannot target a local or
/// special-purpose address. DNS names still require address pinning by the
/// HTTP adapter immediately before connection.
pub(crate) fn validate_public_https_url(value: &str) -> OauthResult<()> {
    validate_https_url(value, false)?;
    let url = Url::parse(value).map_err(|_| OauthError::new(Reason::InvalidUrl))?;
    match url.host() {
        Some(Host::Ipv4(address)) if !is_public_ip(IpAddr::V4(address)) => {
            Err(OauthError::new(Reason::InvalidUrl))
        }
        Some(Host::Ipv6(address)) if !is_public_ip(IpAddr::V6(address)) => {
            Err(OauthError::new(Reason::InvalidUrl))
        }
        Some(Host::Domain(domain)) if is_localhost_name(domain) => {
            Err(OauthError::new(Reason::InvalidUrl))
        }
        Some(_) => Ok(()),
        None => Err(OauthError::new(Reason::InvalidUrl)),
    }
}

pub(crate) fn is_public_ip(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => {
            let [first, second, third, _] = address.octets();
            !(first == 0
                || address.is_unspecified()
                || address.is_loopback()
                || address.is_private()
                || address.is_link_local()
                || address.is_multicast()
                || address.is_broadcast()
                || address.is_documentation()
                || (first == 100 && (64..=127).contains(&second))
                || (first == 192
                    && second == 0
                    && third == 0
                    && !matches!(address.octets()[3], 9 | 10))
                || (first == 192 && second == 88 && third == 99)
                || (first == 198 && (second == 18 || second == 19))
                || first >= 240)
        }
        IpAddr::V6(address) => {
            let segments = address.segments();
            if let Some(mapped) = address.to_ipv4_mapped() {
                return is_public_ip(IpAddr::V4(mapped));
            }
            if let Some(translated) = ipv4_translated_address(segments) {
                return is_public_ip(IpAddr::V4(translated));
            }
            let ipv4_compatible = segments[..6].iter().all(|segment| *segment == 0);
            let nat64_well_known = segments[0] == 0x0064
                && segments[1] == 0xff9b
                && segments[2..6].iter().all(|segment| *segment == 0);
            let nat64_local_use =
                segments[0] == 0x0064 && segments[1] == 0xff9b && segments[2] == 0x0001;
            let discard_only =
                segments[0] == 0x0100 && segments[1..4].iter().all(|segment| *segment == 0);
            let orchid = segments[0] == 0x2001 && matches!(segments[1] & 0xfff0, 0x0010 | 0x0020);
            let global_unicast = (segments[0] & 0xe000) == 0x2000;
            let amt = segments[0] == 0x2001 && segments[1] == 0x0003;
            let deprecated_eid = segments[0] == 0x2001 && segments[1] == 0x0005;
            let pcp_anycast = segments == [0x2001, 0x0001, 0, 0, 0, 0, 0, 1];
            let as112 = segments[0] == 0x2001 && segments[1] == 0x0004 && segments[2] == 0x0112;
            global_unicast
                && !(address.is_unspecified()
                    || address.is_loopback()
                    || address.is_multicast()
                    || ipv4_compatible
                    || nat64_well_known
                    || nat64_local_use
                    || discard_only
                    || orchid
                    || amt
                    || deprecated_eid
                    || pcp_anycast
                    || as112
                    || (segments[0] & 0xfe00) == 0xfc00
                    || (segments[0] & 0xffc0) == 0xfe80
                    || (segments[0] & 0xffc0) == 0xfec0
                    || (segments[0] == 0x2001 && segments[1] == 0)
                    || (segments[0] == 0x2001 && segments[1] == 0x0002 && segments[2] == 0)
                    || (segments[0] == 0x2001 && segments[1] == 0x0db8)
                    || segments[0] == 0x2002
                    || (segments[0] == 0x3fff && segments[1] & 0xf000 == 0)
                    || segments[0] == 0x5f00)
        }
    }
}

fn is_localhost_name(domain: &str) -> bool {
    let canonical = domain.trim_end_matches('.');
    canonical.eq_ignore_ascii_case("localhost")
        || canonical.to_ascii_lowercase().ends_with(".localhost")
        || canonical.eq_ignore_ascii_case("localhost.localdomain")
        || canonical.eq_ignore_ascii_case("ip6-localhost")
        || canonical.eq_ignore_ascii_case("ip6-loopback")
}

fn ipv4_translated_address(segments: [u16; 8]) -> Option<Ipv4Addr> {
    if segments[..4].iter().all(|segment| *segment == 0)
        && segments[4] == u16::MAX
        && segments[5] == 0
    {
        let high = segments[6].to_be_bytes();
        let low = segments[7].to_be_bytes();
        Some(Ipv4Addr::new(high[0], high[1], low[0], low[1]))
    } else {
        None
    }
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
