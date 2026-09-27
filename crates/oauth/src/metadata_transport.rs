// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! DNS-pinned transport boundary for Authorization Server metadata.

use core::fmt;
use core::num::NonZeroU16;
use std::net::IpAddr;

use zeroize::{Zeroize, ZeroizeOnDrop};

use super::{validate_metadata_issuer, AuthorizationServerMetadata};
use crate::error::{OauthError, OauthResult, Reason};
use crate::metadata_url::authorization_server_metadata_url_for_validated_issuer;
use crate::sensitive::zeroize_option;
use crate::validation::{is_public_ip, MAX_JSON_BYTES};

const HTTP_STATUS_OK: u16 = 200;
const HTTP_REDIRECT_STATUS_START: u16 = 300;
const HTTP_REDIRECT_STATUS_END: u16 = 399;
const MAX_METADATA_ADDRESSES: usize = 16;
const MAX_METADATA_MEDIA_TYPE_BYTES: usize = 256;

/// Address class permitted for Authorization Server metadata discovery.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum MetadataAddressPolicy {
    /// Require every resolved address to be publicly routable.
    #[default]
    PublicInternet,
    /// Require every resolved address to be an IPv4 or IPv6 loopback address.
    ///
    /// This exceptional mode exists only for authenticated local OIDF
    /// self-assessment. Callers must not select it from unauthenticated or
    /// attacker-controlled input. HTTPS, hostname authentication, DNS pinning,
    /// exact-port binding, and all response validation remain mandatory.
    LoopbackOnly,
}

/// Authorization Server metadata fetcher injected by HTTP adapters.
pub trait MetadataFetcher {
    /// Resolve every address that may be used for this metadata request.
    /// Empty, mixed, or policy-disallowed results are rejected before HTTP.
    fn resolve_metadata_host(&self, host: &str) -> OauthResult<Vec<IpAddr>>;

    /// Legacy 0.3.1 response hook retained only for source compatibility.
    ///
    /// Hardened discovery never calls this method because a bare string cannot
    /// authenticate transport binding, media type, response size, or redirect
    /// behavior. Adapters must implement `fetch_metadata_response`.
    #[deprecated(
        since = "0.3.2",
        note = "implement fetch_metadata_response with transport evidence"
    )]
    fn fetch_metadata_json(&self, _request: &MetadataFetchRequest) -> OauthResult<String> {
        Err(OauthError::new(Reason::MetadataTransportPolicyUnsupported))
    }

    /// Fetch a bounded raw response with connection-binding evidence.
    ///
    /// The adapter must connect only to `request.approved_addresses()` at
    /// `request.port()`, retain `request.host()` for TLS SNI and certificate
    /// validation, disable automatic redirects, and stop reading at
    /// `request.max_response_bytes()`. It must report the actual connection and
    /// effective URL; discovery rejects any mismatch before parsing JSON.
    fn fetch_metadata_response(
        &self,
        _request: &MetadataFetchRequest,
    ) -> OauthResult<MetadataFetchResponse> {
        Err(OauthError::new(Reason::MetadataTransportPolicyUnsupported))
    }
}

/// Validated, DNS-bound RFC 8414 metadata request passed to an HTTP adapter.
pub struct MetadataFetchRequest {
    url: String,
    host: String,
    port: NonZeroU16,
    approved_addresses: Vec<IpAddr>,
    address_policy: MetadataAddressPolicy,
}

impl MetadataFetchRequest {
    /// Exact well-known URL to request without following redirects.
    #[must_use]
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Hostname retained for TLS SNI and certificate verification.
    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    /// Validated destination port for the pinned connection.
    #[must_use]
    pub const fn port(&self) -> NonZeroU16 {
        self.port
    }

    /// Policy-approved addresses to which the adapter must pin the connection.
    #[must_use]
    pub fn approved_addresses(&self) -> &[IpAddr] {
        &self.approved_addresses
    }

    /// Address classification applied to every approved DNS result.
    #[must_use]
    pub const fn address_policy(&self) -> MetadataAddressPolicy {
        self.address_policy
    }

    /// Maximum response bytes the adapter may read.
    #[must_use]
    pub const fn max_response_bytes(&self) -> usize {
        MAX_JSON_BYTES
    }

    /// Metadata discovery never permits automatic redirect following.
    #[must_use]
    pub const fn redirects_allowed(&self) -> bool {
        false
    }
}

impl fmt::Debug for MetadataFetchRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MetadataFetchRequest([REDACTED])")
    }
}

/// Transport evidence binding a response to the validated request authority.
pub struct MetadataConnectionEvidence {
    peer_address: IpAddr,
    peer_port: NonZeroU16,
    authenticated_host: String,
    effective_url: String,
}

impl MetadataConnectionEvidence {
    /// Creates evidence reported by the HTTPS adapter after certificate and
    /// hostname validation has succeeded.
    #[must_use]
    pub fn new(
        peer_address: IpAddr,
        peer_port: NonZeroU16,
        authenticated_host: String,
        effective_url: String,
    ) -> Self {
        Self {
            peer_address,
            peer_port,
            authenticated_host,
            effective_url,
        }
    }
}

impl fmt::Debug for MetadataConnectionEvidence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MetadataConnectionEvidence([REDACTED])")
    }
}

impl Zeroize for MetadataConnectionEvidence {
    fn zeroize(&mut self) {
        self.peer_address = IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED);
        self.peer_port = NonZeroU16::MIN;
        self.authenticated_host.zeroize();
        self.effective_url.zeroize();
    }
}

impl Drop for MetadataConnectionEvidence {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for MetadataConnectionEvidence {}

/// Bounded HTTP response returned by a metadata transport adapter.
pub struct MetadataFetchResponse {
    status: u16,
    content_type: Option<String>,
    content_length: Option<u64>,
    redirect_location: Option<String>,
    body: Vec<u8>,
    connection: MetadataConnectionEvidence,
}

impl MetadataFetchResponse {
    /// Creates a raw response for validation by the discovery boundary.
    #[must_use]
    pub fn new(
        status: u16,
        content_type: Option<String>,
        content_length: Option<u64>,
        redirect_location: Option<String>,
        body: Vec<u8>,
        connection: MetadataConnectionEvidence,
    ) -> Self {
        Self {
            status,
            content_type,
            content_length,
            redirect_location,
            body,
            connection,
        }
    }
}

impl fmt::Debug for MetadataFetchResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MetadataFetchResponse([REDACTED])")
    }
}

impl Zeroize for MetadataFetchResponse {
    fn zeroize(&mut self) {
        self.status = 0;
        zeroize_option(&mut self.content_type);
        self.content_length = None;
        zeroize_option(&mut self.redirect_location);
        self.body.zeroize();
        self.body.clear();
        self.connection.zeroize();
    }
}

impl Drop for MetadataFetchResponse {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for MetadataFetchResponse {}

/// Fetches and validates RFC 8414 Authorization Server metadata.
pub fn fetch_authorization_server_metadata(
    fetcher: &dyn MetadataFetcher,
    issuer: &str,
) -> OauthResult<AuthorizationServerMetadata> {
    fetch_authorization_server_metadata_with_policy(
        fetcher,
        issuer,
        MetadataAddressPolicy::default(),
    )
}

/// Fetches and validates metadata under an explicit destination policy.
pub fn fetch_authorization_server_metadata_with_policy(
    fetcher: &dyn MetadataFetcher,
    issuer: &str,
    address_policy: MetadataAddressPolicy,
) -> OauthResult<AuthorizationServerMetadata> {
    validate_metadata_issuer(issuer, address_policy)?;
    let metadata_url = authorization_server_metadata_url_for_validated_issuer(issuer)?;
    let parsed = url::Url::parse(&metadata_url).map_err(|_| OauthError::new(Reason::InvalidUrl))?;
    let host = parsed
        .host_str()
        .ok_or_else(|| OauthError::new(Reason::InvalidUrl))?
        .to_owned();
    let port = parsed
        .port_or_known_default()
        .and_then(NonZeroU16::new)
        .ok_or_else(|| OauthError::new(Reason::InvalidUrl))?;
    let approved_addresses = fetcher.resolve_metadata_host(&host)?;
    validate_metadata_addresses(address_policy, &approved_addresses)?;
    let request = MetadataFetchRequest {
        url: metadata_url,
        host,
        port,
        approved_addresses,
        address_policy,
    };
    let response = fetcher.fetch_metadata_response(&request)?;
    validate_connection_binding(&request, &response)?;
    validate_metadata_http_response(&response)?;
    let body =
        core::str::from_utf8(&response.body).map_err(|_| OauthError::new(Reason::InvalidJson))?;
    let metadata =
        AuthorizationServerMetadata::parse_json_with_address_policy(body, address_policy)?;
    if metadata.issuer != issuer {
        return Err(OauthError::new(Reason::AuthorizationServerIssuerMismatch));
    }
    Ok(metadata)
}

fn validate_metadata_addresses(
    address_policy: MetadataAddressPolicy,
    addresses: &[IpAddr],
) -> OauthResult<()> {
    if addresses.is_empty() || addresses.len() > MAX_METADATA_ADDRESSES {
        return Err(OauthError::new(Reason::InvalidUrl));
    }
    let all_allowed = match address_policy {
        MetadataAddressPolicy::PublicInternet => {
            addresses.iter().all(|address| is_public_ip(*address))
        }
        MetadataAddressPolicy::LoopbackOnly => addresses.iter().all(IpAddr::is_loopback),
    };
    if !all_allowed {
        return Err(OauthError::new(Reason::InvalidUrl));
    }
    Ok(())
}

fn validate_connection_binding(
    request: &MetadataFetchRequest,
    response: &MetadataFetchResponse,
) -> OauthResult<()> {
    if !request
        .approved_addresses
        .contains(&response.connection.peer_address)
        || request.port != response.connection.peer_port
        || request.host != response.connection.authenticated_host
    {
        return Err(OauthError::new(Reason::MetadataConnectionBindingFailed));
    }
    if request.url != response.connection.effective_url {
        return Err(OauthError::new(Reason::MetadataRedirectRejected));
    }
    Ok(())
}

fn validate_metadata_http_response(response: &MetadataFetchResponse) -> OauthResult<()> {
    if (HTTP_REDIRECT_STATUS_START..=HTTP_REDIRECT_STATUS_END).contains(&response.status)
        || response.redirect_location.is_some()
    {
        return Err(OauthError::new(Reason::MetadataRedirectRejected));
    }
    if response.status != HTTP_STATUS_OK {
        return Err(OauthError::new(Reason::MetadataHttpStatusRejected));
    }
    if response.body.len() > MAX_JSON_BYTES
        || response.content_length.is_some_and(|length| {
            usize::try_from(length)
                .map(|value| value > MAX_JSON_BYTES || value != response.body.len())
                .unwrap_or(true)
        })
    {
        return Err(OauthError::new(Reason::MetadataResponseTooLarge));
    }
    validate_metadata_media_type(response.content_type.as_deref())
}

fn validate_metadata_media_type(value: Option<&str>) -> OauthResult<()> {
    let value = value.ok_or_else(|| OauthError::new(Reason::MetadataMediaTypeRejected))?;
    if value.is_empty()
        || value.len() > MAX_METADATA_MEDIA_TYPE_BYTES
        || value.chars().any(char::is_control)
    {
        return Err(OauthError::new(Reason::MetadataMediaTypeRejected));
    }
    let mut parts = value.split(';');
    let base = parts
        .next()
        .ok_or_else(|| OauthError::new(Reason::MetadataMediaTypeRejected))?;
    if !base.trim().eq_ignore_ascii_case("application/json") {
        return Err(OauthError::new(Reason::MetadataMediaTypeRejected));
    }
    let mut saw_charset = false;
    for parameter in parts {
        let (name, parameter_value) = parameter
            .split_once('=')
            .ok_or_else(|| OauthError::new(Reason::MetadataMediaTypeRejected))?;
        let parameter_value = parameter_value.trim();
        let parameter_value = parameter_value
            .strip_prefix('"')
            .and_then(|inner| inner.strip_suffix('"'))
            .unwrap_or(parameter_value);
        if saw_charset
            || !name.trim().eq_ignore_ascii_case("charset")
            || !parameter_value.eq_ignore_ascii_case("utf-8")
        {
            return Err(OauthError::new(Reason::MetadataMediaTypeRejected));
        }
        saw_charset = true;
    }
    Ok(())
}
