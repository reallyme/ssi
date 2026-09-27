// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::cell::Cell;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::num::NonZeroU16;

use super::{
    fetch_authorization_server_metadata, fetch_authorization_server_metadata_with_policy,
    MetadataAddressPolicy, MetadataConnectionEvidence, MetadataFetchRequest, MetadataFetchResponse,
    MetadataFetcher,
};
use crate::{OauthResult, Reason};

struct StaticMetadata(&'static str);

impl MetadataFetcher for StaticMetadata {
    fn resolve_metadata_host(&self, _host: &str) -> OauthResult<Vec<IpAddr>> {
        Ok(vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))])
    }

    fn fetch_metadata_response(
        &self,
        request: &MetadataFetchRequest,
    ) -> OauthResult<MetadataFetchResponse> {
        bound_response(
            request,
            self.0.as_bytes().to_vec(),
            IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
        )
    }
}

struct AddressMetadata {
    addresses: Vec<IpAddr>,
    fetch_called: Cell<bool>,
}

struct PortCapturingMetadata {
    body: &'static str,
    observed_port: Cell<Option<NonZeroU16>>,
}

impl MetadataFetcher for PortCapturingMetadata {
    fn resolve_metadata_host(&self, _host: &str) -> OauthResult<Vec<IpAddr>> {
        Ok(vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))])
    }

    fn fetch_metadata_response(
        &self,
        request: &MetadataFetchRequest,
    ) -> OauthResult<MetadataFetchResponse> {
        self.observed_port.set(Some(request.port()));
        bound_response(
            request,
            self.body.as_bytes().to_vec(),
            IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
        )
    }
}

impl MetadataFetcher for AddressMetadata {
    fn resolve_metadata_host(&self, _host: &str) -> OauthResult<Vec<IpAddr>> {
        Ok(self.addresses.clone())
    }

    fn fetch_metadata_response(
        &self,
        _request: &MetadataFetchRequest,
    ) -> OauthResult<MetadataFetchResponse> {
        self.fetch_called.set(true);
        Err(crate::OauthError::new(Reason::InvalidMetadata))
    }
}

fn bound_response(
    request: &MetadataFetchRequest,
    body: Vec<u8>,
    peer_address: IpAddr,
) -> OauthResult<MetadataFetchResponse> {
    let content_length = u64::try_from(body.len())
        .map_err(|_| crate::OauthError::new(Reason::MetadataResponseTooLarge))?;
    Ok(MetadataFetchResponse::new(
        200,
        Some("application/json".to_owned()),
        Some(content_length),
        None,
        body,
        MetadataConnectionEvidence::new(
            peer_address,
            request.port(),
            request.host().to_owned(),
            request.url().to_owned(),
        ),
    ))
}

#[derive(Clone, Copy)]
enum HardenedResponse {
    Valid,
    ValidLocalEndpoints,
    CrossHostEndpoint,
    MissingMediaType,
    HttpFailure,
    DeclaredLengthMismatch,
    WrongPeer,
    WrongPort,
    WrongHostname,
    RedirectStatus,
    RedirectLocation,
    ChangedEffectiveUrl,
    WrongMediaType,
    OversizedBody,
    OversizedDeclaredLength,
    IssuerMismatch,
    TlsFailure,
}

struct HardenedMetadata {
    addresses: Vec<IpAddr>,
    issuer: &'static str,
    response: HardenedResponse,
    fetch_called: Cell<bool>,
    observed_port: Cell<Option<NonZeroU16>>,
    observed_policy: Cell<Option<MetadataAddressPolicy>>,
    observed_redirects_allowed: Cell<Option<bool>>,
    observed_max_response_bytes: Cell<Option<usize>>,
}

impl HardenedMetadata {
    fn new(addresses: Vec<IpAddr>, issuer: &'static str, response: HardenedResponse) -> Self {
        Self {
            addresses,
            issuer,
            response,
            fetch_called: Cell::new(false),
            observed_port: Cell::new(None),
            observed_policy: Cell::new(None),
            observed_redirects_allowed: Cell::new(None),
            observed_max_response_bytes: Cell::new(None),
        }
    }
}

impl MetadataFetcher for HardenedMetadata {
    fn resolve_metadata_host(&self, _host: &str) -> OauthResult<Vec<IpAddr>> {
        Ok(self.addresses.clone())
    }

    fn fetch_metadata_response(
        &self,
        request: &MetadataFetchRequest,
    ) -> OauthResult<MetadataFetchResponse> {
        self.fetch_called.set(true);
        self.observed_port.set(Some(request.port()));
        self.observed_policy.set(Some(request.address_policy()));
        self.observed_redirects_allowed
            .set(Some(request.redirects_allowed()));
        self.observed_max_response_bytes
            .set(Some(request.max_response_bytes()));
        if matches!(self.response, HardenedResponse::TlsFailure) {
            return Err(crate::OauthError::new(Reason::MetadataTlsFailure));
        }

        let mut peer_address = request
            .approved_addresses()
            .first()
            .copied()
            .ok_or_else(|| crate::OauthError::new(Reason::InvalidUrl))?;
        let mut peer_port = request.port();
        let mut authenticated_host = request.host().to_owned();
        let mut effective_url = request.url().to_owned();
        let mut status = 200;
        let mut content_type = Some("application/json; charset=utf-8".to_owned());
        let mut redirect_location = None;
        let mut body = format!(r#"{{"issuer":"{}"}}"#, self.issuer).into_bytes();
        let mut content_length = u64::try_from(body.len()).ok();

        match self.response {
            HardenedResponse::Valid | HardenedResponse::TlsFailure => {}
            HardenedResponse::ValidLocalEndpoints => {
                body = format!(
                    r#"{{"issuer":"{}","authorization_endpoint":"https://localhost:9443/authorize","token_endpoint":"https://localhost:9443/token"}}"#,
                    self.issuer,
                )
                .into_bytes();
                content_length = u64::try_from(body.len()).ok();
            }
            HardenedResponse::CrossHostEndpoint => {
                body = format!(
                    r#"{{"issuer":"{}","token_endpoint":"https://10.0.0.1/token"}}"#,
                    self.issuer,
                )
                .into_bytes();
                content_length = u64::try_from(body.len()).ok();
            }
            HardenedResponse::MissingMediaType => {
                content_type = None;
            }
            HardenedResponse::HttpFailure => {
                status = 500;
            }
            HardenedResponse::DeclaredLengthMismatch => {
                content_length = content_length.and_then(|length| length.checked_add(1));
            }
            HardenedResponse::WrongPeer => {
                peer_address = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2));
            }
            HardenedResponse::WrongPort => {
                peer_port = NonZeroU16::new(request.port().get().saturating_add(1))
                    .ok_or_else(|| crate::OauthError::new(Reason::InvalidUrl))?;
            }
            HardenedResponse::WrongHostname => {
                authenticated_host = "other.example".to_owned();
            }
            HardenedResponse::RedirectStatus => {
                status = 302;
                redirect_location = Some("https://other.example/metadata".to_owned());
                body.clear();
                content_length = Some(0);
            }
            HardenedResponse::RedirectLocation => {
                redirect_location = Some(request.url().to_owned());
            }
            HardenedResponse::ChangedEffectiveUrl => {
                effective_url = "https://other.example/metadata".to_owned();
            }
            HardenedResponse::WrongMediaType => {
                content_type = Some("text/html".to_owned());
            }
            HardenedResponse::OversizedBody => {
                body = vec![b' '; request.max_response_bytes().saturating_add(1)];
                content_length = u64::try_from(body.len()).ok();
            }
            HardenedResponse::OversizedDeclaredLength => {
                content_length = u64::try_from(request.max_response_bytes())
                    .ok()
                    .and_then(|length| length.checked_add(1));
            }
            HardenedResponse::IssuerMismatch => {
                body = br#"{"issuer":"https://other.example"}"#.to_vec();
                content_length = u64::try_from(body.len()).ok();
            }
        }

        Ok(MetadataFetchResponse::new(
            status,
            content_type,
            content_length,
            redirect_location,
            body,
            MetadataConnectionEvidence::new(
                peer_address,
                peer_port,
                authenticated_host,
                effective_url,
            ),
        ))
    }
}

struct ResolverOnlyMetadata;

impl MetadataFetcher for ResolverOnlyMetadata {
    fn resolve_metadata_host(&self, _host: &str) -> OauthResult<Vec<IpAddr>> {
        Ok(vec![IpAddr::V4(Ipv4Addr::LOCALHOST)])
    }
}

#[test]
fn passes_the_default_https_port_to_the_fetcher() -> OauthResult<()> {
    let fetcher = PortCapturingMetadata {
        body: r#"{"issuer":"https://issuer.example"}"#,
        observed_port: Cell::new(None),
    };

    fetch_authorization_server_metadata(&fetcher, "https://issuer.example")?;

    assert_eq!(fetcher.observed_port.get().map(NonZeroU16::get), Some(443));
    Ok(())
}

#[test]
fn preserves_an_explicit_https_port_for_the_fetcher() -> OauthResult<()> {
    let fetcher = PortCapturingMetadata {
        body: r#"{"issuer":"https://issuer.example:8443"}"#,
        observed_port: Cell::new(None),
    };

    fetch_authorization_server_metadata(&fetcher, "https://issuer.example:8443")?;

    assert_eq!(fetcher.observed_port.get().map(NonZeroU16::get), Some(8443));
    Ok(())
}

#[test]
fn rejects_an_explicit_zero_port_before_fetching() {
    let fetcher = AddressMetadata {
        addresses: vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))],
        fetch_called: Cell::new(false),
    };

    let result = fetch_authorization_server_metadata(&fetcher, "https://issuer.example:0");

    assert!(matches!(result, Err(error) if error.reason() == Reason::InvalidUrl));
    assert!(!fetcher.fetch_called.get());
}

#[test]
fn loopback_policy_accepts_https_ipv4_and_ipv6_and_preserves_the_exact_port() -> OauthResult<()> {
    for (issuer, address, expected_port) in [
        (
            "https://127.0.0.1:8443",
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            8443,
        ),
        ("https://[::1]:9443", IpAddr::V6(Ipv6Addr::LOCALHOST), 9443),
    ] {
        let fetcher = HardenedMetadata::new(vec![address], issuer, HardenedResponse::Valid);
        let metadata = fetch_authorization_server_metadata_with_policy(
            &fetcher,
            issuer,
            MetadataAddressPolicy::LoopbackOnly,
        )?;

        assert_eq!(metadata.issuer, issuer);
        assert_eq!(
            fetcher.observed_port.get().map(NonZeroU16::get),
            Some(expected_port),
        );
        assert_eq!(
            fetcher.observed_policy.get(),
            Some(MetadataAddressPolicy::LoopbackOnly),
        );
        assert_eq!(fetcher.observed_redirects_allowed.get(), Some(false));
        assert_eq!(
            fetcher.observed_max_response_bytes.get(),
            Some(crate::validation::MAX_JSON_BYTES),
        );
    }
    Ok(())
}

#[test]
fn loopback_policy_rejects_empty_mixed_and_non_loopback_resolution_before_fetch() {
    let rejected = [
        Vec::new(),
        vec![
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
        ],
        vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))],
        vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))],
    ];
    for addresses in rejected {
        let fetcher =
            HardenedMetadata::new(addresses, "https://localhost:8443", HardenedResponse::Valid);
        let result = fetch_authorization_server_metadata_with_policy(
            &fetcher,
            "https://localhost:8443",
            MetadataAddressPolicy::LoopbackOnly,
        );
        assert!(matches!(result, Err(error) if error.reason() == Reason::InvalidUrl));
        assert!(!fetcher.fetch_called.get());
    }
}

#[test]
fn loopback_policy_still_requires_https() {
    let fetcher = HardenedMetadata::new(
        vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
        "http://localhost:8443",
        HardenedResponse::Valid,
    );
    let result = fetch_authorization_server_metadata_with_policy(
        &fetcher,
        "http://localhost:8443",
        MetadataAddressPolicy::LoopbackOnly,
    );
    assert!(matches!(result, Err(error) if error.reason() == Reason::InvalidUrl));
    assert!(!fetcher.fetch_called.get());
}

#[test]
fn loopback_policy_rejects_wrong_peer_address_port_and_authenticated_hostname() {
    for (response, expected) in [
        (
            HardenedResponse::WrongPeer,
            Reason::MetadataConnectionBindingFailed,
        ),
        (
            HardenedResponse::WrongPort,
            Reason::MetadataConnectionBindingFailed,
        ),
        (
            HardenedResponse::WrongHostname,
            Reason::MetadataConnectionBindingFailed,
        ),
    ] {
        let fetcher = HardenedMetadata::new(
            vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
            "https://localhost:8443",
            response,
        );
        let result = fetch_authorization_server_metadata_with_policy(
            &fetcher,
            "https://localhost:8443",
            MetadataAddressPolicy::LoopbackOnly,
        );
        assert!(matches!(result, Err(error) if error.reason() == expected));
    }
}

#[test]
fn loopback_policy_rejects_redirects_in_every_reported_form() {
    for response in [
        HardenedResponse::RedirectStatus,
        HardenedResponse::RedirectLocation,
        HardenedResponse::ChangedEffectiveUrl,
    ] {
        let fetcher = HardenedMetadata::new(
            vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
            "https://localhost:8443",
            response,
        );
        let result = fetch_authorization_server_metadata_with_policy(
            &fetcher,
            "https://localhost:8443",
            MetadataAddressPolicy::LoopbackOnly,
        );
        assert!(matches!(
            result,
            Err(error) if error.reason() == Reason::MetadataRedirectRejected
        ));
    }
}

#[test]
fn loopback_policy_rejects_tls_certificate_and_hostname_failures() {
    let fetcher = HardenedMetadata::new(
        vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
        "https://localhost:8443",
        HardenedResponse::TlsFailure,
    );
    let result = fetch_authorization_server_metadata_with_policy(
        &fetcher,
        "https://localhost:8443",
        MetadataAddressPolicy::LoopbackOnly,
    );
    assert!(matches!(
        result,
        Err(error) if error.reason() == Reason::MetadataTlsFailure
    ));
}

#[test]
fn loopback_policy_rejects_wrong_media_type_and_oversized_documents() {
    for (response, expected) in [
        (
            HardenedResponse::MissingMediaType,
            Reason::MetadataMediaTypeRejected,
        ),
        (
            HardenedResponse::WrongMediaType,
            Reason::MetadataMediaTypeRejected,
        ),
        (
            HardenedResponse::HttpFailure,
            Reason::MetadataHttpStatusRejected,
        ),
        (
            HardenedResponse::DeclaredLengthMismatch,
            Reason::MetadataResponseTooLarge,
        ),
        (
            HardenedResponse::OversizedBody,
            Reason::MetadataResponseTooLarge,
        ),
        (
            HardenedResponse::OversizedDeclaredLength,
            Reason::MetadataResponseTooLarge,
        ),
    ] {
        let fetcher = HardenedMetadata::new(
            vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
            "https://localhost:8443",
            response,
        );
        let result = fetch_authorization_server_metadata_with_policy(
            &fetcher,
            "https://localhost:8443",
            MetadataAddressPolicy::LoopbackOnly,
        );
        assert!(matches!(result, Err(error) if error.reason() == expected));
    }
}

#[test]
fn discovery_fails_closed_when_the_adapter_lacks_the_hardened_transport_hook() {
    let result = fetch_authorization_server_metadata_with_policy(
        &ResolverOnlyMetadata,
        "https://localhost:8443",
        MetadataAddressPolicy::LoopbackOnly,
    );
    assert!(matches!(
        result,
        Err(error) if error.reason() == Reason::MetadataTransportPolicyUnsupported
    ));
}

#[test]
fn loopback_policy_binds_the_authenticated_metadata_issuer_exactly() {
    let fetcher = HardenedMetadata::new(
        vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
        "https://localhost:8443",
        HardenedResponse::IssuerMismatch,
    );
    let result = fetch_authorization_server_metadata_with_policy(
        &fetcher,
        "https://localhost:8443",
        MetadataAddressPolicy::LoopbackOnly,
    );
    assert!(matches!(
        result,
        Err(error) if error.reason() == Reason::AuthorizationServerIssuerMismatch
    ));
}

#[test]
fn loopback_policy_keeps_advertised_endpoints_on_the_authenticated_host() -> OauthResult<()> {
    let accepted = HardenedMetadata::new(
        vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
        "https://localhost:8443",
        HardenedResponse::ValidLocalEndpoints,
    );
    fetch_authorization_server_metadata_with_policy(
        &accepted,
        "https://localhost:8443",
        MetadataAddressPolicy::LoopbackOnly,
    )?;

    let rejected = HardenedMetadata::new(
        vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
        "https://localhost:8443",
        HardenedResponse::CrossHostEndpoint,
    );
    let result = fetch_authorization_server_metadata_with_policy(
        &rejected,
        "https://localhost:8443",
        MetadataAddressPolicy::LoopbackOnly,
    );
    assert!(matches!(result, Err(error) if error.reason() == Reason::InvalidUrl));
    Ok(())
}

#[test]
fn accepts_additional_rfc8414_metadata_parameters() {
    let metadata = super::AuthorizationServerMetadata::parse_json(
        r#"{
            "issuer":"https://issuer.example",
            "scopes_supported":["openid","credential"],
            "service_documentation":"https://issuer.example/documentation",
            "example_extension":{"enabled":true}
        }"#,
    );

    assert!(metadata.is_ok());
}

#[test]
fn distinguishes_an_authenticated_metadata_issuer_mismatch() {
    let result = fetch_authorization_server_metadata(
        &StaticMetadata(r#"{"issuer":"https://other.example"}"#),
        "https://issuer.example",
    );
    assert!(matches!(
        result,
        Err(error) if error.reason() == Reason::AuthorizationServerIssuerMismatch
    ));
}

#[test]
fn preserves_other_metadata_validation_failures() {
    let result = fetch_authorization_server_metadata(
        &StaticMetadata(r#"{"issuer":"http://issuer.example"}"#),
        "https://issuer.example",
    );
    assert!(matches!(
        result,
        Err(error) if error.reason() == Reason::InvalidUrl
    ));
}

#[test]
fn rejects_private_metadata_targets_before_fetch() {
    let rejected = [
        IpAddr::V4(Ipv4Addr::new(0, 1, 2, 3)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(169, 254, 1, 1)),
        IpAddr::V4(Ipv4Addr::new(192, 88, 99, 1)),
        IpAddr::V4(Ipv4Addr::new(192, 31, 196, 1)),
        IpAddr::V4(Ipv4Addr::new(192, 52, 193, 1)),
        IpAddr::V4(Ipv4Addr::new(192, 175, 48, 1)),
        IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0xc000, 0x0201)),
        IpAddr::V6(Ipv6Addr::new(0x0064, 0xff9b, 0, 0, 0, 0, 0x7f00, 1)),
        IpAddr::V6(Ipv6Addr::new(0x0064, 0xff9b, 1, 0, 0, 0, 0xa9fe, 0xa9fe)),
        IpAddr::V6(Ipv6Addr::new(0x2002, 0x7f00, 1, 0, 0, 0, 0, 0)),
        IpAddr::V6(Ipv6Addr::new(0x2001, 0, 0, 0, 0, 0, 0, 1)),
        IpAddr::V6(Ipv6Addr::new(0x2001, 0x0010, 0, 0, 0, 0, 0, 1)),
        IpAddr::V6(Ipv6Addr::new(0x2001, 0x0020, 0, 0, 0, 0, 0, 1)),
        IpAddr::V6(Ipv6Addr::new(0x2001, 0x0002, 0, 0, 0, 0, 0, 1)),
        IpAddr::V6(Ipv6Addr::new(0x3fff, 0x0001, 0, 0, 0, 0, 0, 1)),
        IpAddr::V6(Ipv6Addr::new(0x2620, 0x004f, 0x8000, 0, 0, 0, 0, 1)),
        IpAddr::V6(Ipv6Addr::new(0x5f00, 0, 0, 0, 0, 0, 0, 1)),
        IpAddr::V6(Ipv6Addr::new(0x0100, 0, 0, 0, 0, 0, 0, 1)),
    ];
    for address in rejected {
        let fetcher = AddressMetadata {
            addresses: vec![address],
            fetch_called: Cell::new(false),
        };
        let result = fetch_authorization_server_metadata(&fetcher, "https://issuer.example");
        assert!(matches!(result, Err(error) if error.reason() == Reason::InvalidUrl));
        assert!(!fetcher.fetch_called.get());
    }
}

#[test]
fn rejects_private_literal_issuers_before_resolution() {
    for issuer in [
        "https://127.0.0.1",
        "https://[::1]",
        "https://localhost./",
        "https://localhost../",
        "https://[::ffff:0:169.254.169.254]",
    ] {
        let fetcher = AddressMetadata {
            addresses: vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))],
            fetch_called: Cell::new(false),
        };
        let result = fetch_authorization_server_metadata(&fetcher, issuer);
        assert!(matches!(result, Err(error) if error.reason() == Reason::InvalidUrl));
        assert!(!fetcher.fetch_called.get(), "{issuer}");
    }
}

#[test]
fn accepts_public_addresses_in_the_rest_of_192_0_slash_16() {
    let fetcher = AddressMetadata {
        addresses: vec![IpAddr::V4(Ipv4Addr::new(192, 0, 1, 1))],
        fetch_called: Cell::new(false),
    };
    let result = fetch_authorization_server_metadata(&fetcher, "https://issuer.example");
    assert!(result.is_err());
    assert!(fetcher.fetch_called.get());
}

#[test]
fn accepts_globally_reachable_ietf_protocol_assignment_anycast_addresses() {
    for last in [9, 10] {
        let fetcher = AddressMetadata {
            addresses: vec![IpAddr::V4(Ipv4Addr::new(192, 0, 0, last))],
            fetch_called: Cell::new(false),
        };
        let result = fetch_authorization_server_metadata(&fetcher, "https://issuer.example");
        assert!(result.is_err());
        assert!(fetcher.fetch_called.get());
    }
}

#[test]
fn rejects_non_global_192_0_0_addresses() {
    let fetcher = AddressMetadata {
        addresses: vec![IpAddr::V4(Ipv4Addr::new(192, 0, 0, 11))],
        fetch_called: Cell::new(false),
    };
    let result = fetch_authorization_server_metadata(&fetcher, "https://issuer.example");
    assert!(matches!(result, Err(error) if error.reason() == Reason::InvalidUrl));
    assert!(!fetcher.fetch_called.get());
}

#[test]
fn rejects_local_literal_metadata_endpoints() {
    for field in [
        "authorization_endpoint",
        "token_endpoint",
        "pushed_authorization_request_endpoint",
        "challenge_endpoint",
        "jwks_uri",
    ] {
        for endpoint in [
            "https://0.1.2.3/token",
            "https://127.0.0.1/token",
            "https://169.254.169.254/token",
            "https://[::1]/token",
            "https://[::a9fe:a9fe]/token",
            "https://[64:ff9b::a9fe:a9fe]/token",
            "https://[64:ff9b:1::a9fe:a9fe]/token",
            "https://[100::1]/token",
            "https://[2001:10::1]/token",
            "https://[2001:20::1]/token",
            "https://[2001::1]/token",
            "https://[2002:a9fe:a9fe::1]/token",
            "https://localhost/token",
            "https://localhost./token",
            "https://[::ffff:0:169.254.169.254]/token",
        ] {
            let body = format!(r#"{{"issuer":"https://issuer.example","{field}":"{endpoint}"}}"#);
            let result = super::AuthorizationServerMetadata::parse_json(&body);
            assert!(matches!(result, Err(error) if error.reason() == Reason::InvalidUrl));
        }
    }
}
