// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(clippy::arithmetic_side_effects)]
//! End-to-end profile tests for did:web semantics and injected boundaries.

use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr};

use reallyme_did_method_web::{
    canonicalize_did_web, dereference_did_web_document, did_web_document_url,
    parse_and_validate_did_web_document,
    parse_and_validate_did_web_document_with_json_ld_processor, parse_did_web,
    resolve_did_web_document, resolve_did_web_document_with_json_ld_processor,
    AuthenticatedDidWebHostingProvider, DidWebCancellation, DidWebDocumentLimits, DidWebError,
    DidWebErrorReason, DidWebHostingError, DidWebHostingOperation, DidWebHostingReceipt,
    DidWebHttpRequest, DidWebHttpResponse, DidWebJsonLdError, DidWebJsonLdErrorReason,
    DidWebJsonLdProcessor, DidWebNetworkResolver, DidWebPublicationRequest, DidWebResolutionPolicy,
    DidWebTransportError, PublicInternetDestinationPolicy,
};

const DID: &str = "did:web:example.com";
const PUBLIC_ADDRESS: IpAddr = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));

struct NeverCancelled;

impl DidWebCancellation for NeverCancelled {
    fn is_cancelled(&self) -> bool {
        false
    }
}

struct AlwaysCancelled;

impl DidWebCancellation for AlwaysCancelled {
    fn is_cancelled(&self) -> bool {
        true
    }
}

struct AcceptJsonLd;

impl DidWebJsonLdProcessor for AcceptJsonLd {
    fn validate_json_ld(&self, _document_json: &[u8]) -> Result<(), DidWebJsonLdError> {
        Ok(())
    }
}

struct RejectJsonLd;

impl DidWebJsonLdProcessor for RejectJsonLd {
    fn validate_json_ld(&self, _document_json: &[u8]) -> Result<(), DidWebJsonLdError> {
        Err(DidWebJsonLdError::new(
            DidWebJsonLdErrorReason::InvalidDocument,
        ))
    }
}

struct MockNetwork {
    dns: RefCell<VecDeque<Vec<IpAddr>>>,
    responses: RefCell<VecDeque<DidWebHttpResponse>>,
    urls: RefCell<Vec<String>>,
}

impl MockNetwork {
    fn new(dns: Vec<Vec<IpAddr>>, responses: Vec<DidWebHttpResponse>) -> Self {
        Self {
            dns: RefCell::new(dns.into()),
            responses: RefCell::new(responses.into()),
            urls: RefCell::new(Vec::new()),
        }
    }
}

impl DidWebNetworkResolver for MockNetwork {
    fn resolve_dns(
        &self,
        _domain: &str,
        _port: u16,
        _timeout: std::time::Duration,
    ) -> Result<Vec<IpAddr>, DidWebTransportError> {
        self.dns.borrow_mut().pop_front().ok_or_else(|| {
            DidWebTransportError::new(reallyme_did_method_web::DidWebTransportErrorReason::Dns)
        })
    }

    fn get_https(
        &self,
        request: DidWebHttpRequest<'_>,
    ) -> Result<DidWebHttpResponse, DidWebTransportError> {
        self.urls.borrow_mut().push(request.url.as_str().to_owned());
        self.responses.borrow_mut().pop_front().ok_or_else(|| {
            DidWebTransportError::new(reallyme_did_method_web::DidWebTransportErrorReason::Network)
        })
    }
}

struct MockHostingProvider {
    authenticated: bool,
    calls: Cell<usize>,
    wrong_receipt: bool,
}

impl AuthenticatedDidWebHostingProvider for MockHostingProvider {
    fn is_authenticated_for(&self, _operation: DidWebHostingOperation) -> bool {
        self.authenticated
    }

    fn execute(
        &self,
        request: DidWebPublicationRequest<'_>,
    ) -> Result<DidWebHostingReceipt, DidWebHostingError> {
        self.calls.set(self.calls.get() + 1);
        let operation = if self.wrong_receipt {
            DidWebHostingOperation::Deactivate
        } else {
            request.operation
        };
        Ok(DidWebHostingReceipt { operation })
    }
}

#[test]
fn identifier_canonicalization_and_url_derivation_are_strict() {
    assert_eq!(
        canonicalize_did_web("did:web:EXAMPLE.com%3a3000:user:%7earchive"),
        Ok("did:web:example.com%3A3000:user:%7Earchive".to_owned())
    );
    assert_eq!(
        did_web_document_url("did:web:example.com%3A3000:user:%7Earchive"),
        Ok("https://example.com:3000/user/%7Earchive/did.json".to_owned())
    );
    assert_eq!(
        canonicalize_did_web("did:web:EXAMPLE.com%3a03000:user:%2farchive")
            .map_err(|error| error.reason),
        Err(DidWebErrorReason::InvalidPath)
    );
    assert_eq!(
        parse_did_web("did:web:example.com%3a3000").map_err(|error| error.reason),
        Err(DidWebErrorReason::InvalidPercentEncoding)
    );
    assert_eq!(
        parse_did_web("did:web:example.com:user:%7earchive").map_err(|error| error.reason),
        Err(DidWebErrorReason::InvalidPercentEncoding)
    );
    assert_eq!(
        parse_did_web("did:web:example.com%3A03000").map_err(|error| error.reason),
        Err(DidWebErrorReason::InvalidPort)
    );
    for (invalid, expected) in [
        ("did:web:example.com:.", DidWebErrorReason::InvalidPath),
        ("did:web:example.com:..", DidWebErrorReason::InvalidPath),
        (
            "did:web:example.com:%2E%2E",
            DidWebErrorReason::InvalidPercentEncoding,
        ),
        ("did:web:example.com:a%2Fb", DidWebErrorReason::InvalidPath),
        ("did:web:example.com:a%5Cb", DidWebErrorReason::InvalidPath),
        ("did:web:example.com:a%00b", DidWebErrorReason::InvalidPath),
        (
            "did:web:example.com:user@admin",
            DidWebErrorReason::InvalidPath,
        ),
        (
            "did:web:example.com:user?role=admin",
            DidWebErrorReason::InvalidPath,
        ),
        (
            "did:web:example.com:user#key-1",
            DidWebErrorReason::InvalidPath,
        ),
        (
            "did:web:example.com:user~archive",
            DidWebErrorReason::InvalidPath,
        ),
        (
            "did:web:example.com:%61",
            DidWebErrorReason::InvalidPercentEncoding,
        ),
        (
            "did:web:example.com:a%2Eb",
            DidWebErrorReason::InvalidPercentEncoding,
        ),
    ] {
        assert_eq!(
            parse_did_web(invalid).map_err(|error| error.reason),
            Err(expected)
        );
    }
    let oversized = format!("did:web:example.com:{}", "a".repeat(4_096));
    assert_eq!(
        parse_did_web(&oversized).map_err(|error| error.reason),
        Err(DidWebErrorReason::IdentifierTooLong)
    );
}

#[test]
fn document_validation_accepts_absolute_canonical_relationships(
) -> Result<(), Box<dyn std::error::Error>> {
    let identifier = parse_did_web(DID)?;
    let document = parse_and_validate_did_web_document(
        &identifier,
        &document_json(DID),
        DidWebDocumentLimits::default(),
    )?;
    assert_eq!(document.id(), Some(DID));
    Ok(())
}

#[test]
fn did_url_dereferencing_selects_document_and_absolute_fragment(
) -> Result<(), Box<dyn std::error::Error>> {
    let identifier = parse_did_web(DID)?;
    let document = parse_and_validate_did_web_document(
        &identifier,
        &document_json(DID),
        DidWebDocumentLimits::default(),
    )?;
    let selected_document = dereference_did_web_document(&document, DID)?;
    assert_eq!(selected_document.as_bytes(), document.as_bytes());

    let fragment = dereference_did_web_document(&document, "did:web:example.com#key-1")?;
    let fragment_json: serde_json::Value = serde_json::from_slice(fragment.as_bytes())?;
    assert_eq!(
        fragment_json.get("id").and_then(serde_json::Value::as_str),
        Some("did:web:example.com#key-1")
    );
    assert_eq!(
        dereference_did_web_document(&document, "did:web:other.example#key-1")
            .err()
            .map(|error| error.reason),
        Some(DidWebErrorReason::DocumentIdentifierMismatch)
    );
    assert_eq!(
        dereference_did_web_document(&document, "#key-1")
            .err()
            .map(|error| error.reason),
        Some(DidWebErrorReason::InvalidDidUrl)
    );
    Ok(())
}

#[test]
fn document_validation_rejects_mismatch_relative_urls_and_dangling_relationships(
) -> Result<(), Box<dyn std::error::Error>> {
    let identifier = parse_did_web(DID)?;
    let mismatched = document_json("did:web:other.example");
    assert_eq!(
        parse_and_validate_did_web_document(
            &identifier,
            &mismatched,
            DidWebDocumentLimits::default()
        )
        .err()
        .map(|error| error.reason),
        Some(DidWebErrorReason::DocumentIdentifierMismatch)
    );

    let relative = document_json_with_authentication(DID, "#key-1");
    assert_eq!(
        parse_and_validate_did_web_document(
            &identifier,
            &relative,
            DidWebDocumentLimits::default()
        )
        .err()
        .map(|error| error.reason),
        Some(DidWebErrorReason::InvalidDidUrl)
    );

    let dangling = document_json_with_authentication(DID, "did:web:example.com#missing");
    assert_eq!(
        parse_and_validate_did_web_document(
            &identifier,
            &dangling,
            DidWebDocumentLimits::default()
        )
        .err()
        .map(|error| error.reason),
        Some(DidWebErrorReason::UnresolvedRelationshipReference)
    );
    Ok(())
}

#[test]
fn document_validation_rejects_private_jwk_material_and_excessive_depth(
) -> Result<(), Box<dyn std::error::Error>> {
    let identifier = parse_did_web(DID)?;
    let private_key = document_json_with_private_jwk(DID);
    assert_eq!(
        parse_and_validate_did_web_document(
            &identifier,
            &private_key,
            DidWebDocumentLimits::default()
        )
        .err()
        .map(|error| error.reason),
        Some(DidWebErrorReason::InvalidVerificationMethod)
    );

    let deep = br#"{"id":"did:web:example.com","nested":{"a":{"b":{"c":true}}}}"#;
    let limits = DidWebDocumentLimits {
        max_depth: 3,
        ..DidWebDocumentLimits::default()
    };
    assert_eq!(
        parse_and_validate_did_web_document(&identifier, deep, limits)
            .err()
            .map(|error| error.reason),
        Some(DidWebErrorReason::JsonDepthExceeded)
    );
    Ok(())
}

#[test]
fn document_validation_rejects_noncanonical_did_url_percent_encoding(
) -> Result<(), Box<dyn std::error::Error>> {
    let identifier = parse_did_web(DID)?;
    let invalid_controller = br#"{
        "id":"did:web:example.com",
        "controller":"did:example:controller with space"
    }"#;
    assert_eq!(
        parse_and_validate_did_web_document(
            &identifier,
            invalid_controller,
            DidWebDocumentLimits::default(),
        )
        .err()
        .map(|error| error.reason),
        Some(DidWebErrorReason::InvalidController),
    );

    for method_id in ["k%65y-1", "key%3a1"] {
        let document = format!(
            r#"{{"id":"{DID}","verificationMethod":[{{"id":"{DID}#{method_id}","type":"Multikey","controller":"{DID}","publicKeyMultibase":"z6Mkf5rGMoatrSj1f4CyvuHBeXJELe9RPdzo2PKGNCKVtZxP"}}]}}"#
        );
        assert_eq!(
            parse_and_validate_did_web_document(
                &identifier,
                document.as_bytes(),
                DidWebDocumentLimits::default(),
            )
            .err()
            .map(|error| error.reason),
            Some(DidWebErrorReason::InvalidDidUrl),
        );
    }
    Ok(())
}

#[test]
fn document_validation_enforces_did_core_sets_uris_and_service_shapes(
) -> Result<(), Box<dyn std::error::Error>> {
    let identifier = parse_did_web(DID)?;
    let valid = format!(
        r#"{{"@context":["https://www.w3.org/ns/did/v1",{{"Example":"https://example.com/vocab#"}}],"id":"{DID}","controller":["{DID}"],"alsoKnownAs":["https://example.com/identities/alice"],"service":[{{"id":"https://example.com/services/inbox","type":["MessagingService","Example"],"serviceEndpoint":["https://example.com/inbox",{{"uri":"https://backup.example/inbox"}}]}}]}}"#
    );
    parse_and_validate_did_web_document_with_json_ld_processor(
        &identifier,
        valid.as_bytes(),
        DidWebDocumentLimits::default(),
        &AcceptJsonLd,
    )?;

    let invalid_documents = [
        format!(r#"{{"id":"{DID}","controller":["{DID}","{DID}"]}}"#),
        format!(r#"{{"id":"{DID}","authentication":[]}}"#),
        format!(
            r#"{{"id":"{DID}","alsoKnownAs":["https://example.com/id","https://example.com/id"]}}"#
        ),
        format!(
            r#"{{"@context":["https://example.com/context","https://www.w3.org/ns/did/v1"],"id":"{DID}"}}"#
        ),
        format!(
            r#"{{"id":"{DID}","authentication":["did:web:controller.example#key-1","did:web:controller.example#key-1"]}}"#
        ),
        format!(
            r#"{{"id":"{DID}","service":[{{"id":"{DID}#inbox","type":[],"serviceEndpoint":"https://example.com/inbox"}}]}}"#
        ),
        format!(
            r#"{{"id":"{DID}","service":[{{"id":"{DID}#inbox","type":"MessagingService","serviceEndpoint":"relative/path"}}]}}"#
        ),
        format!(
            r#"{{"id":"{DID}","service":[{{"id":"{DID}#inbox","type":"MessagingService","serviceEndpoint":[]}}]}}"#
        ),
    ];
    for document in invalid_documents {
        assert!(parse_and_validate_did_web_document_with_json_ld_processor(
            &identifier,
            document.as_bytes(),
            DidWebDocumentLimits::default(),
            &AcceptJsonLd,
        )
        .is_err());
    }
    Ok(())
}

#[test]
fn json_ld_documents_require_successful_injected_processing(
) -> Result<(), Box<dyn std::error::Error>> {
    let identifier = parse_did_web(DID)?;
    let document = format!(r#"{{"@context":["https://www.w3.org/ns/did/v1"],"id":"{DID}"}}"#);
    assert_eq!(
        parse_and_validate_did_web_document(
            &identifier,
            document.as_bytes(),
            DidWebDocumentLimits::default(),
        )
        .err()
        .map(|error| error.reason),
        Some(DidWebErrorReason::JsonLdProcessorUnavailable),
    );
    assert_eq!(
        parse_and_validate_did_web_document_with_json_ld_processor(
            &identifier,
            document.as_bytes(),
            DidWebDocumentLimits::default(),
            &RejectJsonLd,
        )
        .err()
        .map(|error| error.reason),
        Some(DidWebErrorReason::InvalidJsonLd),
    );
    parse_and_validate_did_web_document_with_json_ld_processor(
        &identifier,
        document.as_bytes(),
        DidWebDocumentLimits::default(),
        &AcceptJsonLd,
    )?;

    let network = MockNetwork::new(
        vec![vec![PUBLIC_ADDRESS]],
        vec![success_response(document.into_bytes(), PUBLIC_ADDRESS)],
    );
    resolve_did_web_document_with_json_ld_processor(
        &network,
        &PublicInternetDestinationPolicy,
        &NeverCancelled,
        DID,
        DidWebResolutionPolicy::default(),
        &AcceptJsonLd,
    )?;
    Ok(())
}

#[test]
fn document_validation_applies_did_jwk_rules_to_embedded_keys(
) -> Result<(), Box<dyn std::error::Error>> {
    let identifier = parse_did_web(DID)?;
    for invalid_jwk in [
        r#"{"kty":"OKP","crv":"Ed25519","x":"not+padded="}"#,
        r#"{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo","use":"sig","key_ops":["deriveBits"]}"#,
    ] {
        let document = format!(
            r#"{{"id":"{DID}","verificationMethod":[{{"id":"{DID}#key-1","type":"JsonWebKey2020","controller":"{DID}","publicKeyJwk":{invalid_jwk}}}]}}"#
        );
        assert_eq!(
            parse_and_validate_did_web_document(
                &identifier,
                document.as_bytes(),
                DidWebDocumentLimits::default(),
            )
            .err()
            .map(|error| error.reason),
            Some(DidWebErrorReason::InvalidVerificationMethod),
        );
    }
    Ok(())
}

#[test]
fn resolver_pins_dns_and_validates_document_and_media_type(
) -> Result<(), Box<dyn std::error::Error>> {
    let network = MockNetwork::new(
        vec![vec![PUBLIC_ADDRESS]],
        vec![success_response(document_json(DID), PUBLIC_ADDRESS)],
    );
    let result = resolve_did_web_document(
        &network,
        &PublicInternetDestinationPolicy,
        &NeverCancelled,
        DID,
        DidWebResolutionPolicy::default(),
    )?;
    assert_eq!(result.document.id(), Some(DID));
    assert_eq!(result.redirect_count, 0);
    assert_eq!(
        network.urls.borrow().as_slice(),
        ["https://example.com/.well-known/did.json"]
    );
    Ok(())
}

#[test]
fn resolver_rechecks_redirect_dns_and_rejects_http_redirects(
) -> Result<(), Box<dyn std::error::Error>> {
    let redirect = DidWebHttpResponse {
        status: 302,
        content_type: None,
        content_length: None,
        redirect_location: Some("https://cdn.example.com/did.json".to_owned()),
        body: Vec::new(),
        peer_address: PUBLIC_ADDRESS,
    };
    let network = MockNetwork::new(
        vec![vec![PUBLIC_ADDRESS], vec![PUBLIC_ADDRESS]],
        vec![
            redirect,
            success_response(document_json(DID), PUBLIC_ADDRESS),
        ],
    );
    let result = resolve_did_web_document(
        &network,
        &PublicInternetDestinationPolicy,
        &NeverCancelled,
        DID,
        DidWebResolutionPolicy::default(),
    )?;
    assert_eq!(result.redirect_count, 1);

    let insecure = DidWebHttpResponse {
        status: 302,
        content_type: None,
        content_length: None,
        redirect_location: Some("http://cdn.example.com/did.json".to_owned()),
        body: Vec::new(),
        peer_address: PUBLIC_ADDRESS,
    };
    let network = MockNetwork::new(vec![vec![PUBLIC_ADDRESS]], vec![insecure]);
    assert_eq!(
        resolve_did_web_document(
            &network,
            &PublicInternetDestinationPolicy,
            &NeverCancelled,
            DID,
            DidWebResolutionPolicy::default()
        )
        .err()
        .map(|error| error.reason),
        Some(DidWebErrorReason::HttpsRequired)
    );

    for rejected_location in [
        "https://user@cdn.example.com/did.json",
        "https://cdn.example.com/did.json#document",
        "https://example.com/.well-known/did.json",
    ] {
        let rejected = DidWebHttpResponse {
            status: 302,
            content_type: None,
            content_length: None,
            redirect_location: Some(rejected_location.to_owned()),
            body: Vec::new(),
            peer_address: PUBLIC_ADDRESS,
        };
        let network = MockNetwork::new(vec![vec![PUBLIC_ADDRESS]], vec![rejected]);
        assert_resolution_reason(
            &network,
            &NeverCancelled,
            DidWebErrorReason::RedirectPolicyViolation,
        );
    }

    let bounded = DidWebHttpResponse {
        status: 302,
        content_type: None,
        content_length: None,
        redirect_location: Some("https://cdn.example.com/did.json".to_owned()),
        body: Vec::new(),
        peer_address: PUBLIC_ADDRESS,
    };
    let network = MockNetwork::new(vec![vec![PUBLIC_ADDRESS]], vec![bounded]);
    let policy = DidWebResolutionPolicy {
        max_redirects: 0,
        ..DidWebResolutionPolicy::default()
    };
    assert_eq!(
        resolve_did_web_document(
            &network,
            &PublicInternetDestinationPolicy,
            &NeverCancelled,
            DID,
            policy,
        )
        .err()
        .map(|error| error.reason),
        Some(DidWebErrorReason::RedirectPolicyViolation),
    );
    Ok(())
}

#[test]
fn transport_failures_map_to_stable_privacy_safe_reasons() {
    use reallyme_did_method_web::DidWebTransportErrorReason;

    for (transport, expected) in [
        (
            DidWebTransportErrorReason::Dns,
            DidWebErrorReason::DnsResolutionFailed,
        ),
        (
            DidWebTransportErrorReason::Network,
            DidWebErrorReason::NetworkFailure,
        ),
        (
            DidWebTransportErrorReason::Tls,
            DidWebErrorReason::TlsFailure,
        ),
        (
            DidWebTransportErrorReason::Timeout,
            DidWebErrorReason::Timeout,
        ),
        (
            DidWebTransportErrorReason::Cancelled,
            DidWebErrorReason::Cancelled,
        ),
    ] {
        let mapped = DidWebError::from(DidWebTransportError::new(transport));
        assert_eq!(mapped.reason, expected);
    }
}

#[test]
fn resolver_rejects_private_dns_rebinding_media_size_and_cancellation() {
    let private = MockNetwork::new(
        vec![vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]],
        vec![success_response(
            document_json(DID),
            IpAddr::V4(Ipv4Addr::LOCALHOST),
        )],
    );
    assert_resolution_reason(
        &private,
        &NeverCancelled,
        DidWebErrorReason::DestinationDenied,
    );

    let rebinding = MockNetwork::new(
        vec![vec![PUBLIC_ADDRESS]],
        vec![success_response(
            document_json(DID),
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
        )],
    );
    assert_resolution_reason(
        &rebinding,
        &NeverCancelled,
        DidWebErrorReason::DnsRebindingDetected,
    );

    let mut wrong_media = success_response(document_json(DID), PUBLIC_ADDRESS);
    wrong_media.content_type = Some("text/html".to_owned());
    let media = MockNetwork::new(vec![vec![PUBLIC_ADDRESS]], vec![wrong_media]);
    assert_resolution_reason(
        &media,
        &NeverCancelled,
        DidWebErrorReason::UnsupportedMediaType,
    );

    let mut oversized = success_response(document_json(DID), PUBLIC_ADDRESS);
    oversized.content_length = Some(u64::MAX);
    let size = MockNetwork::new(vec![vec![PUBLIC_ADDRESS]], vec![oversized]);
    assert_resolution_reason(&size, &NeverCancelled, DidWebErrorReason::ResponseTooLarge);

    let cancelled = MockNetwork::new(Vec::new(), Vec::new());
    assert_resolution_reason(&cancelled, &AlwaysCancelled, DidWebErrorReason::Cancelled);
}

#[path = "did_web_profile_tests/provider_tests.rs"]
mod provider_tests;

#[test]
fn resolver_rejects_ipv6_transition_prefixes_embedding_private_ipv4(
) -> Result<(), Box<dyn std::error::Error>> {
    for address in [
        // 6to4 for 127.0.0.1
        "2002:7f00:1::1",
        // Teredo
        "2001:0:4136:e378:8000:63bf:3fff:fdd2",
        // Benchmarking and ORCHIDv2
        "2001:2::1",
        "2001:20::1",
    ] {
        let address: IpAddr = address.parse()?;
        let network = MockNetwork::new(
            vec![vec![address]],
            vec![success_response(document_json(DID), address)],
        );
        assert_resolution_reason(
            &network,
            &NeverCancelled,
            DidWebErrorReason::DestinationDenied,
        );
    }
    Ok(())
}

#[test]
fn resolver_parses_media_type_case_insensitively() -> Result<(), Box<dyn std::error::Error>> {
    for content_type in [
        "Application/DID+JSON",
        "application/did+json; Charset=UTF-8",
        "application/did+json ; charset=\"utf-8\"",
    ] {
        let mut response = success_response(document_json(DID), PUBLIC_ADDRESS);
        response.content_type = Some(content_type.to_owned());
        let network = MockNetwork::new(vec![vec![PUBLIC_ADDRESS]], vec![response]);
        resolve_did_web_document(
            &network,
            &PublicInternetDestinationPolicy,
            &NeverCancelled,
            DID,
            DidWebResolutionPolicy::default(),
        )?;
    }

    let mut response = success_response(document_json(DID), PUBLIC_ADDRESS);
    response.content_type = Some("application/did+json; charset=iso-8859-1".to_owned());
    let network = MockNetwork::new(vec![vec![PUBLIC_ADDRESS]], vec![response]);
    assert_resolution_reason(
        &network,
        &NeverCancelled,
        DidWebErrorReason::UnsupportedMediaType,
    );
    Ok(())
}

fn assert_resolution_reason(
    network: &MockNetwork,
    cancellation: &dyn DidWebCancellation,
    expected: DidWebErrorReason,
) {
    assert_eq!(
        resolve_did_web_document(
            network,
            &PublicInternetDestinationPolicy,
            cancellation,
            DID,
            DidWebResolutionPolicy::default()
        )
        .err()
        .map(|error| error.reason),
        Some(expected)
    );
}

fn success_response(body: Vec<u8>, peer_address: IpAddr) -> DidWebHttpResponse {
    let content_length = u64::try_from(body.len()).ok();
    DidWebHttpResponse {
        status: 200,
        content_type: Some("application/did+json;charset=utf-8".to_owned()),
        content_length,
        redirect_location: None,
        body,
        peer_address,
    }
}

fn document_json(did: &str) -> Vec<u8> {
    document_json_with_authentication(did, &format!("{did}#key-1"))
}

fn document_json_with_authentication(did: &str, authentication: &str) -> Vec<u8> {
    format!(
        r#"{{"id":"{did}","controller":"{did}","verificationMethod":[{{"id":"{did}#key-1","type":"Multikey","controller":"{did}","publicKeyMultibase":"z6Mkf5rGMoatrSj1f4CyvuHBeXJELe9RPdzo2PKGNCKVtZxP"}}],"authentication":["{authentication}"],"assertionMethod":["{did}#key-1"],"service":[{{"id":"{did}#inbox","type":"MessagingService","serviceEndpoint":"https://example.com/inbox"}}]}}"#
    )
    .into_bytes()
}

fn document_json_with_private_jwk(did: &str) -> Vec<u8> {
    format!(
        r#"{{"id":"{did}","verificationMethod":[{{"id":"{did}#key-1","type":"JsonWebKey2020","controller":"{did}","publicKeyJwk":{{"kty":"OKP","crv":"Ed25519","x":"public","d":"private"}}}}]}}"#
    )
    .into_bytes()
}

#[test]
fn rejects_duplicate_document_members() -> Result<(), Box<dyn std::error::Error>> {
    let identifier = parse_did_web(DID)?;
    let bytes = br#"{"id":"did:web:attacker.example","id":"did:web:example.com"}"#;
    assert_eq!(
        parse_and_validate_did_web_document(&identifier, bytes, DidWebDocumentLimits::default())
            .err()
            .map(|error| error.reason),
        Some(DidWebErrorReason::InvalidDocument)
    );
    Ok(())
}
