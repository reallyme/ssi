// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{
    did_web_document_url, generate_did_web, parse_did_web, DidWebErrorReason, WebDidInput,
};

#[test]
fn bare_domain_maps_to_well_known_did_json() -> Result<(), Box<dyn std::error::Error>> {
    let did = generate_did_web(WebDidInput {
        domain: "example.com",
        port: None,
        path_segments: &[],
    })?;

    assert_eq!(did, "did:web:example.com");
    assert_eq!(
        did_web_document_url(&did)?,
        "https://example.com/.well-known/did.json"
    );
    Ok(())
}

#[test]
fn published_w3c_ccg_examples_map_to_did_json_locations() -> Result<(), Box<dyn std::error::Error>>
{
    let cases = [
        (
            "did:web:w3c-ccg.github.io",
            "https://w3c-ccg.github.io/.well-known/did.json",
        ),
        (
            "did:web:w3c-ccg.github.io:user:alice",
            "https://w3c-ccg.github.io/user/alice/did.json",
        ),
        (
            "did:web:example.com%3A3000:user:alice",
            "https://example.com:3000/user/alice/did.json",
        ),
    ];

    for (did, expected_url) in cases {
        parse_did_web(did)?;
        assert_eq!(did_web_document_url(did)?, expected_url);
    }
    Ok(())
}

#[test]
fn path_and_port_follow_did_web_mapping_rules() -> Result<(), Box<dyn std::error::Error>> {
    let did = generate_did_web(WebDidInput {
        domain: "example.com",
        port: Some(3000),
        path_segments: &["user", "alice"],
    })?;

    assert_eq!(did, "did:web:example.com%3A3000:user:alice");
    assert_eq!(
        did_web_document_url(&did)?,
        "https://example.com:3000/user/alice/did.json"
    );
    Ok(())
}

#[test]
fn did_web_rejects_ip_addresses() {
    for did in [
        "did:web:192.0.2.1",
        "did:web:127.1",
        "did:web:0x7f.1",
        "did:web:0177.0.0.1",
        "did:web:10.0.1",
    ] {
        let err = parse_did_web(did).err().map(|error| error.reason);
        assert_eq!(err, Some(DidWebErrorReason::InvalidDomain));
    }
    assert_eq!(
        parse_did_web("did:web:example.com%3A443")
            .err()
            .map(|error| error.reason),
        Some(DidWebErrorReason::InvalidPort)
    );
}

#[test]
fn did_web_raw_colon_is_path_not_port() -> Result<(), Box<dyn std::error::Error>> {
    let did = "did:web:example.com:3000";
    parse_did_web(did)?;
    assert_eq!(
        did_web_document_url(did)?,
        "https://example.com/3000/did.json"
    );
    Ok(())
}

#[test]
fn did_web_rejects_path_normalization_aliases() {
    for did in [
        "did:web:example.com:.",
        "did:web:example.com:..",
        "did:web:example.com:a%2Fb",
        "did:web:example.com:a%5Cb",
        "did:web:example.com:a%00b",
        "did:web:example.com:a%1Fb",
        "did:web:example.com:a%7Fb",
    ] {
        assert_eq!(
            parse_did_web(did).err().map(|error| error.reason),
            Some(DidWebErrorReason::InvalidPath)
        );
    }

    for did in [
        "did:web:example.com:%61",
        "did:web:example.com:%2E",
        "did:web:example.com:%2E%2E",
        "did:web:example.com:a%2Eb",
    ] {
        assert_eq!(
            parse_did_web(did).err().map(|error| error.reason),
            Some(DidWebErrorReason::InvalidPercentEncoding)
        );
    }
}

#[test]
fn did_web_generates_and_parses_encoded_tilde_path_segment(
) -> Result<(), Box<dyn std::error::Error>> {
    let did = generate_did_web(WebDidInput {
        domain: "example.com",
        port: None,
        path_segments: &["~alice"],
    })?;
    assert_eq!(did, "did:web:example.com:%7Ealice");
    assert_eq!(
        parse_did_web(&did)?.path_segments(),
        ["%7Ealice".to_owned()]
    );
    assert_eq!(
        parse_did_web("did:web:example.com:%7ealice")
            .err()
            .map(|error| error.reason),
        Some(DidWebErrorReason::InvalidPercentEncoding)
    );
    Ok(())
}

#[test]
fn did_web_rejects_noncanonical_dns_case_and_percent_escapes() {
    assert_eq!(
        parse_did_web("did:web:EXAMPLE.com")
            .err()
            .map(|error| error.reason),
        Some(DidWebErrorReason::InvalidDomain)
    );
    assert_eq!(
        parse_did_web("did:web:example.com:%7e")
            .err()
            .map(|error| error.reason),
        Some(DidWebErrorReason::InvalidPercentEncoding)
    );
}
