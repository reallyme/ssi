// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Fail-closed did:web resolution over injected DNS and HTTPS boundaries.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use url::Url;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::document::{parse_and_validate_did_web_document, DidWebDocument, DidWebDocumentLimits};
use crate::error::{DidWebError, DidWebErrorReason, DidWebTransportError};
use crate::method::{did_web_document_url, parse_did_web, DidWebIdentifier};

const HTTPS_DEFAULT_PORT: u16 = 443;
const HTTP_STATUS_OK: u16 = 200;
const REDIRECT_STATUSES: [u16; 5] = [301, 302, 303, 307, 308];

/// Resolution limits and transport deadlines.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DidWebResolutionPolicy {
    /// Maximum number of redirects followed.
    pub max_redirects: u8,
    /// Document byte, depth, and node limits.
    pub document_limits: DidWebDocumentLimits,
    /// DNS lookup timeout applied per target.
    pub dns_timeout: Duration,
    /// Connection and TLS timeout applied per target.
    pub connect_timeout: Duration,
    /// Whole HTTPS request timeout applied per target.
    pub request_timeout: Duration,
}

impl Default for DidWebResolutionPolicy {
    fn default() -> Self {
        Self {
            max_redirects: 5,
            document_limits: DidWebDocumentLimits::default(),
            dns_timeout: Duration::from_secs(5),
            connect_timeout: Duration::from_secs(5),
            request_timeout: Duration::from_secs(15),
        }
    }
}

/// Media types accepted for a did:web document.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DidWebMediaType {
    /// `application/did+json`.
    ApplicationDidJson,
    /// `application/did+ld+json`.
    ApplicationDidLdJson,
    /// `application/json` permitted by the did:web specification.
    ApplicationJson,
}

/// Cancellation boundary controlled by the caller.
pub trait DidWebCancellation {
    /// Return true when the caller has cancelled the operation.
    fn is_cancelled(&self) -> bool;
}

/// Additional destination policy evaluated for every DNS answer and redirect.
pub trait DidWebDestinationPolicy {
    /// Decide whether this domain/address pair may be contacted.
    fn allows(&self, domain: &str, address: IpAddr) -> bool;
}

/// Default policy allowing only public, globally routable unicast addresses.
#[derive(Debug, Clone, Copy, Default)]
pub struct PublicInternetDestinationPolicy;

impl DidWebDestinationPolicy for PublicInternetDestinationPolicy {
    fn allows(&self, _domain: &str, address: IpAddr) -> bool {
        is_public_unicast(address)
    }
}

/// HTTPS request passed to an injected transport.
///
/// The transport must connect only to `approved_addresses`, retain the URL host
/// for TLS SNI and certificate verification, disable automatic redirects, and
/// stop reading after `max_response_bytes`.
pub struct DidWebHttpRequest<'a> {
    /// Canonical absolute HTTPS URL.
    pub url: &'a Url,
    /// TLS hostname and DNS lookup name.
    pub domain: &'a str,
    /// Explicit or default HTTPS port.
    pub port: u16,
    /// Freshly resolved addresses to which the transport must pin the connection.
    pub approved_addresses: &'a [IpAddr],
    /// Connection and TLS deadline.
    pub connect_timeout: Duration,
    /// Whole request deadline.
    pub request_timeout: Duration,
    /// Maximum body bytes the transport may read.
    pub max_response_bytes: usize,
}

/// Bounded HTTPS response returned by an injected transport.
pub struct DidWebHttpResponse {
    /// Numeric HTTP status.
    pub status: u16,
    /// Untrusted Content-Type header value.
    pub content_type: Option<String>,
    /// Parsed Content-Length when present.
    pub content_length: Option<u64>,
    /// Untrusted Location header when present.
    pub redirect_location: Option<String>,
    /// Bounded response body.
    pub body: Vec<u8>,
    /// Actual connected peer address reported by the transport.
    pub peer_address: IpAddr,
}

impl core::fmt::Debug for DidWebHttpResponse {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("DidWebHttpResponse(<redacted>)")
    }
}

impl Zeroize for DidWebHttpResponse {
    fn zeroize(&mut self) {
        self.status = 0;
        self.content_type.zeroize();
        self.content_length = None;
        self.redirect_location.zeroize();
        self.body.zeroize();
        self.body.clear();
        self.peer_address = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
    }
}

impl Drop for DidWebHttpResponse {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for DidWebHttpResponse {}

/// Network boundary required by the did:web resolution state machine.
pub trait DidWebNetworkResolver {
    /// Resolve a fresh address set for one request target.
    fn resolve_dns(
        &self,
        domain: &str,
        port: u16,
        timeout: Duration,
    ) -> Result<Vec<IpAddr>, DidWebTransportError>;

    /// Execute HTTPS with automatic redirect handling disabled.
    fn get_https(
        &self,
        request: DidWebHttpRequest<'_>,
    ) -> Result<DidWebHttpResponse, DidWebTransportError>;
}

/// Validated resolution output.
pub struct DidWebResolutionResult {
    /// Parsed and validated DID document.
    pub document: DidWebDocument,
    /// Accepted media type.
    pub media_type: DidWebMediaType,
    /// Number of redirects followed.
    pub redirect_count: u8,
}

impl core::fmt::Debug for DidWebResolutionResult {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("DidWebResolutionResult(<redacted>)")
    }
}

/// Resolve and validate a did:web document with no ambient network access.
pub fn resolve_did_web_document(
    network: &dyn DidWebNetworkResolver,
    destination_policy: &dyn DidWebDestinationPolicy,
    cancellation: &dyn DidWebCancellation,
    did: &str,
    policy: DidWebResolutionPolicy,
) -> Result<DidWebResolutionResult, DidWebError> {
    let identifier = parse_did_web(did)?;
    let initial_url = did_web_document_url(identifier.as_str())?;
    let mut current_url = parse_https_url(&initial_url)?;
    let mut visited = vec![current_url.as_str().to_owned()];
    let mut redirect_count = 0u8;

    loop {
        ensure_not_cancelled(cancellation)?;
        let domain = current_url
            .host_str()
            .ok_or(DidWebError::new(DidWebErrorReason::RedirectPolicyViolation))?;
        let port = current_url.port().unwrap_or(HTTPS_DEFAULT_PORT);
        let addresses = network.resolve_dns(domain, port, policy.dns_timeout)?;
        validate_addresses(destination_policy, domain, &addresses)?;
        ensure_not_cancelled(cancellation)?;

        let response = network.get_https(DidWebHttpRequest {
            url: &current_url,
            domain,
            port,
            approved_addresses: &addresses,
            connect_timeout: policy.connect_timeout,
            request_timeout: policy.request_timeout,
            max_response_bytes: policy.document_limits.max_bytes,
        })?;
        ensure_not_cancelled(cancellation)?;
        if !addresses.contains(&response.peer_address) {
            return Err(DidWebError::new(DidWebErrorReason::DnsRebindingDetected));
        }

        if response.status == HTTP_STATUS_OK {
            return finish_resolution(identifier, response, redirect_count, policy);
        }
        if !REDIRECT_STATUSES.contains(&response.status) {
            return Err(DidWebError::new(DidWebErrorReason::HttpStatusRejected));
        }
        if redirect_count >= policy.max_redirects {
            return Err(DidWebError::new(DidWebErrorReason::RedirectPolicyViolation));
        }
        let location = response
            .redirect_location
            .as_deref()
            .ok_or(DidWebError::new(DidWebErrorReason::RedirectPolicyViolation))?;
        let next_url = parse_https_url(location)?;
        if visited.iter().any(|url| url == next_url.as_str()) {
            return Err(DidWebError::new(DidWebErrorReason::RedirectPolicyViolation));
        }
        visited.push(next_url.as_str().to_owned());
        redirect_count = redirect_count
            .checked_add(1)
            .ok_or(DidWebError::new(DidWebErrorReason::RedirectPolicyViolation))?;
        current_url = next_url;
    }
}

fn finish_resolution(
    identifier: DidWebIdentifier,
    response: DidWebHttpResponse,
    redirect_count: u8,
    policy: DidWebResolutionPolicy,
) -> Result<DidWebResolutionResult, DidWebError> {
    if response.redirect_location.is_some() {
        return Err(DidWebError::new(DidWebErrorReason::RedirectPolicyViolation));
    }
    if response.body.len() > policy.document_limits.max_bytes
        || response.content_length.is_some_and(|length| {
            usize::try_from(length)
                .map(|value| value > policy.document_limits.max_bytes)
                .unwrap_or(true)
        })
    {
        return Err(DidWebError::new(DidWebErrorReason::ResponseTooLarge));
    }
    let media_type = parse_media_type(response.content_type.as_deref())?;
    let document = parse_and_validate_did_web_document(
        &identifier,
        response.body.as_slice(),
        policy.document_limits,
    )?;
    Ok(DidWebResolutionResult {
        document,
        media_type,
        redirect_count,
    })
}

fn parse_https_url(value: &str) -> Result<Url, DidWebError> {
    let url = Url::parse(value)
        .map_err(|_| DidWebError::new(DidWebErrorReason::RedirectPolicyViolation))?;
    if url.scheme() != "https" {
        return Err(DidWebError::new(DidWebErrorReason::HttpsRequired));
    }
    if !url.username().is_empty()
        || url.password().is_some()
        || url.host_str().is_none()
        || url
            .host_str()
            .is_some_and(|host| host.parse::<IpAddr>().is_ok())
        || url.query().is_some()
        || url.fragment().is_some()
        || url.as_str() != value
    {
        return Err(DidWebError::new(DidWebErrorReason::RedirectPolicyViolation));
    }
    let host = url
        .host_str()
        .ok_or(DidWebError::new(DidWebErrorReason::RedirectPolicyViolation))?;
    let synthetic_did = if let Some(port) = url.port() {
        let mut did = String::from("did:web:");
        did.push_str(host);
        did.push_str("%3A");
        did.push_str(&port.to_string());
        did
    } else {
        let mut did = String::from("did:web:");
        did.push_str(host);
        did
    };
    parse_did_web(&synthetic_did)
        .map_err(|_| DidWebError::new(DidWebErrorReason::RedirectPolicyViolation))?;
    Ok(url)
}

fn validate_addresses(
    destination_policy: &dyn DidWebDestinationPolicy,
    domain: &str,
    addresses: &[IpAddr],
) -> Result<(), DidWebError> {
    if addresses.is_empty() {
        return Err(DidWebError::new(DidWebErrorReason::DnsResolutionFailed));
    }
    if addresses
        .iter()
        .any(|address| !is_public_unicast(*address) || !destination_policy.allows(domain, *address))
    {
        return Err(DidWebError::new(DidWebErrorReason::DestinationDenied));
    }
    Ok(())
}

fn ensure_not_cancelled(cancellation: &dyn DidWebCancellation) -> Result<(), DidWebError> {
    if cancellation.is_cancelled() {
        Err(DidWebError::new(DidWebErrorReason::Cancelled))
    } else {
        Ok(())
    }
}

fn parse_media_type(value: Option<&str>) -> Result<DidWebMediaType, DidWebError> {
    let value = value.ok_or(DidWebError::new(DidWebErrorReason::UnsupportedMediaType))?;
    let mut parts = value.split(';');
    let base = parts
        .next()
        .ok_or(DidWebError::new(DidWebErrorReason::UnsupportedMediaType))?;
    for parameter in parts {
        if parameter.trim() != "charset=utf-8" {
            return Err(DidWebError::new(DidWebErrorReason::UnsupportedMediaType));
        }
    }
    match base {
        "application/did+json" => Ok(DidWebMediaType::ApplicationDidJson),
        "application/did+ld+json" => Ok(DidWebMediaType::ApplicationDidLdJson),
        "application/json" => Ok(DidWebMediaType::ApplicationJson),
        _ => Err(DidWebError::new(DidWebErrorReason::UnsupportedMediaType)),
    }
}

fn is_public_unicast(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => is_public_ipv4(address),
        IpAddr::V6(address) => is_public_ipv6(address),
    }
}

fn is_public_ipv4(address: Ipv4Addr) -> bool {
    let [a, b, c, _d] = address.octets();
    !(a == 0
        || a == 10
        || a == 127
        || (a == 100 && (64..=127).contains(&b))
        || (a == 169 && b == 254)
        || (a == 172 && (16..=31).contains(&b))
        || (a == 192 && b == 0 && c == 0)
        || (a == 192 && b == 0 && c == 2)
        || (a == 192 && b == 88 && c == 99)
        || (a == 192 && b == 168)
        || (a == 198 && (b == 18 || b == 19))
        || (a == 198 && b == 51 && c == 100)
        || (a == 203 && b == 0 && c == 113)
        || a >= 224)
}

fn is_public_ipv6(address: Ipv6Addr) -> bool {
    if let Some(mapped) = address.to_ipv4_mapped() {
        return is_public_ipv4(mapped);
    }
    let segments = address.segments();
    let is_global_unicast = (segments[0] & 0xe000) == 0x2000;
    let is_documentation = segments[0] == 0x2001 && segments[1] == 0x0db8;
    is_global_unicast && !is_documentation
}
