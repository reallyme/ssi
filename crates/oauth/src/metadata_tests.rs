// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::cell::Cell;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::{fetch_authorization_server_metadata, MetadataFetchRequest, MetadataFetcher};
use crate::{OauthResult, Reason};

struct StaticMetadata(&'static str);

impl MetadataFetcher for StaticMetadata {
    fn resolve_metadata_host(&self, _host: &str) -> OauthResult<Vec<IpAddr>> {
        Ok(vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))])
    }

    fn fetch_metadata_json(&self, _request: &MetadataFetchRequest) -> OauthResult<String> {
        Ok(self.0.to_owned())
    }
}

struct AddressMetadata {
    addresses: Vec<IpAddr>,
    fetch_called: Cell<bool>,
}

impl MetadataFetcher for AddressMetadata {
    fn resolve_metadata_host(&self, _host: &str) -> OauthResult<Vec<IpAddr>> {
        Ok(self.addresses.clone())
    }

    fn fetch_metadata_json(&self, _request: &MetadataFetchRequest) -> OauthResult<String> {
        self.fetch_called.set(true);
        Err(crate::OauthError::new(Reason::InvalidMetadata))
    }
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
