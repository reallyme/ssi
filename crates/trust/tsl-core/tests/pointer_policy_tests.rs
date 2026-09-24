// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(missing_docs, clippy::unwrap_used)]

use identity_trust_tsl_core::{
    parse_tsl_xml, validate_pointer_target, validate_pointer_traversal, PointerTraversalContext,
    PointerTraversalPolicy, TslError, TslMediaType, TslOrigin, TslPointerPolicyFailure,
};

fn list_with_pointer(url: &str) -> String {
    let certificate: String = include_str!("../../tsl-openssl/tests/fixtures/cert.pem")
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect();
    format!(
        r#"<TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#" xmlns:at="http://uri.etsi.org/02231/v2/additionaltypes#" TSLTag="http://uri.etsi.org/19612/TSLTag" Id="TSL"><SchemeInformation><TSLVersionIdentifier>6</TSLVersionIdentifier><TSLSequenceNumber>1</TSLSequenceNumber><TSLType>https://example.test/type</TSLType><SchemeOperatorName><Name xml:lang="en">Operator</Name></SchemeOperatorName><SchemeOperatorAddress><PostalAddresses><PostalAddress xml:lang="en"><StreetAddress>Test Street 1</StreetAddress><Locality>Test City</Locality><CountryName>EU</CountryName></PostalAddress></PostalAddresses><ElectronicAddress><URI xml:lang="en">mailto:trust@example.test</URI><URI xml:lang="en">https://example.test/operator</URI></ElectronicAddress></SchemeOperatorAddress><SchemeName><Name xml:lang="en">Scheme</Name></SchemeName><SchemeInformationURI><URI xml:lang="en">https://example.test/scheme</URI></SchemeInformationURI><StatusDeterminationApproach>https://example.test/status-policy</StatusDeterminationApproach><SchemeTypeCommunityRules><URI xml:lang="en">https://example.test/rules</URI></SchemeTypeCommunityRules><SchemeTerritory>EU</SchemeTerritory><PolicyOrLegalNotice><TSLPolicy xml:lang="en">https://example.test/policy</TSLPolicy></PolicyOrLegalNotice><HistoricalInformationPeriod>65535</HistoricalInformationPeriod><PointersToOtherTSL><OtherTSLPointer><ServiceDigitalIdentities><ServiceDigitalIdentity><DigitalId><X509Certificate>{certificate}</X509Certificate></DigitalId></ServiceDigitalIdentity></ServiceDigitalIdentities><TSLLocation>{url}</TSLLocation><AdditionalInformation><OtherInformation><TSLType>https://example.test/child-type</TSLType></OtherInformation><OtherInformation><SchemeOperatorName><Name xml:lang="en">Child Operator</Name></SchemeOperatorName></OtherInformation><OtherInformation><SchemeTypeCommunityRules><URI xml:lang="en">https://example.test/rules</URI></SchemeTypeCommunityRules></OtherInformation><OtherInformation><SchemeTerritory>EU</SchemeTerritory></OtherInformation><OtherInformation><at:MimeType>application/vnd.etsi.tsl+xml</at:MimeType></OtherInformation></AdditionalInformation></OtherTSLPointer></PointersToOtherTSL><ListIssueDateTime>2026-01-01T00:00:00Z</ListIssueDateTime><NextUpdate><dateTime>2026-02-01T00:00:00Z</dateTime></NextUpdate></SchemeInformation></TrustServiceStatusList>"#
    )
}

fn child_list(territory: &str) -> String {
    format!(
        r#"<TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#" TSLTag="http://uri.etsi.org/19612/TSLTag" Id="CHILD"><SchemeInformation><TSLVersionIdentifier>6</TSLVersionIdentifier><TSLSequenceNumber>1</TSLSequenceNumber><TSLType>https://example.test/child-type</TSLType><SchemeOperatorName><Name xml:lang="en">Child Operator</Name></SchemeOperatorName><SchemeOperatorAddress><PostalAddresses><PostalAddress xml:lang="en"><StreetAddress>Test Street 1</StreetAddress><Locality>Test City</Locality><CountryName>EU</CountryName></PostalAddress></PostalAddresses><ElectronicAddress><URI xml:lang="en">mailto:trust@example.test</URI><URI xml:lang="en">https://example.test/operator</URI></ElectronicAddress></SchemeOperatorAddress><SchemeName><Name xml:lang="en">Child</Name></SchemeName><SchemeInformationURI><URI xml:lang="en">https://example.test/scheme</URI></SchemeInformationURI><StatusDeterminationApproach>https://example.test/status-policy</StatusDeterminationApproach><SchemeTypeCommunityRules><URI xml:lang="en">https://example.test/rules</URI></SchemeTypeCommunityRules><SchemeTerritory>{territory}</SchemeTerritory><PolicyOrLegalNotice><TSLPolicy xml:lang="en">https://example.test/policy</TSLPolicy></PolicyOrLegalNotice><HistoricalInformationPeriod>65535</HistoricalInformationPeriod><ListIssueDateTime>2026-01-01T00:00:00Z</ListIssueDateTime><NextUpdate><dateTime>2026-02-01T00:00:00Z</dateTime></NextUpdate></SchemeInformation></TrustServiceStatusList>"#
    )
}

fn policy() -> PointerTraversalPolicy {
    PointerTraversalPolicy {
        max_depth: 2,
        max_documents: 4,
        max_total_bytes: 1_024,
        require_https: true,
        allowed_origins: vec![TslOrigin::parse("https://example.test").unwrap()],
        allowed_media_types: vec![
            TslMediaType::EtsiTrustedListXml,
            TslMediaType::ApplicationXml,
            TslMediaType::TextXml,
        ],
    }
}

#[test]
fn accepts_bounded_https_pointer() {
    let list = parse_tsl_xml(&list_with_pointer("https://example.test/one")).unwrap();
    let context = PointerTraversalContext {
        depth: 1,
        documents_seen: 1,
        total_bytes_seen: 128,
        fetched_bytes: 256,
        fetched_media_type: TslMediaType::ApplicationXml,
        target: &list.pointers[0].url,
        ancestor_urls: &[],
    };
    assert_eq!(validate_pointer_traversal(&context, &policy()), Ok(()));
}

#[test]
fn binds_authenticated_pointer_qualifiers_to_fetched_child() {
    let parent = parse_tsl_xml(&list_with_pointer("https://example.test/one")).unwrap();
    let child = parse_tsl_xml(&child_list("EU")).unwrap();
    assert_eq!(
        validate_pointer_target(
            &parent.pointers[0],
            &child,
            TslMediaType::EtsiTrustedListXml,
        ),
        Ok(())
    );

    let substituted = parse_tsl_xml(&child_list("US")).unwrap();
    assert_eq!(
        validate_pointer_target(
            &parent.pointers[0],
            &substituted,
            TslMediaType::EtsiTrustedListXml,
        ),
        Err(TslError::PointerPolicy(
            TslPointerPolicyFailure::TargetMetadataMismatch
        ))
    );
}

#[test]
fn rejects_each_pointer_policy_violation() {
    let https = parse_tsl_xml(&list_with_pointer("https://example.test/one")).unwrap();
    let http = parse_tsl_xml(&list_with_pointer("http://example.test/one")).unwrap();
    let other_origin = parse_tsl_xml(&list_with_pointer("https://other.test/one")).unwrap();
    let target = &https.pointers[0].url;
    let cases = [
        (
            PointerTraversalContext {
                depth: 3,
                documents_seen: 0,
                total_bytes_seen: 0,
                fetched_bytes: 0,
                fetched_media_type: TslMediaType::ApplicationXml,
                target,
                ancestor_urls: &[],
            },
            TslPointerPolicyFailure::Depth,
        ),
        (
            PointerTraversalContext {
                depth: 0,
                documents_seen: 4,
                total_bytes_seen: 0,
                fetched_bytes: 0,
                fetched_media_type: TslMediaType::ApplicationXml,
                target,
                ancestor_urls: &[],
            },
            TslPointerPolicyFailure::DocumentCount,
        ),
        (
            PointerTraversalContext {
                depth: 0,
                documents_seen: 0,
                total_bytes_seen: 1_000,
                fetched_bytes: 25,
                fetched_media_type: TslMediaType::ApplicationXml,
                target,
                ancestor_urls: &[],
            },
            TslPointerPolicyFailure::TotalBytes,
        ),
        (
            PointerTraversalContext {
                depth: 0,
                documents_seen: 0,
                total_bytes_seen: 0,
                fetched_bytes: 0,
                fetched_media_type: TslMediaType::ApplicationXml,
                target: &http.pointers[0].url,
                ancestor_urls: &[],
            },
            TslPointerPolicyFailure::InsecureTransport,
        ),
        (
            PointerTraversalContext {
                depth: 0,
                documents_seen: 0,
                total_bytes_seen: 0,
                fetched_bytes: 0,
                fetched_media_type: TslMediaType::ApplicationXml,
                target,
                ancestor_urls: core::slice::from_ref(target),
            },
            TslPointerPolicyFailure::Cycle,
        ),
        (
            PointerTraversalContext {
                depth: 0,
                documents_seen: 0,
                total_bytes_seen: 0,
                fetched_bytes: 0,
                fetched_media_type: TslMediaType::ApplicationXml,
                target: &other_origin.pointers[0].url,
                ancestor_urls: &[],
            },
            TslPointerPolicyFailure::Origin,
        ),
        (
            PointerTraversalContext {
                depth: 0,
                documents_seen: 0,
                total_bytes_seen: 0,
                fetched_bytes: 0,
                fetched_media_type: TslMediaType::Unsupported,
                target,
                ancestor_urls: &[],
            },
            TslPointerPolicyFailure::MediaType,
        ),
    ];

    for (context, expected) in cases {
        assert_eq!(
            validate_pointer_traversal(&context, &policy()),
            Err(TslError::PointerPolicy(expected))
        );
    }
}

#[test]
fn content_type_and_origin_parsing_are_canonical_and_fail_closed() {
    assert_eq!(
        TslMediaType::parse("application/vnd.etsi.tsl+xml"),
        TslMediaType::EtsiTrustedListXml
    );
    assert_eq!(
        TslMediaType::parse("Application/XML; charset=utf-8"),
        TslMediaType::ApplicationXml
    );
    assert_eq!(
        TslMediaType::parse("application/json"),
        TslMediaType::Unsupported
    );
    assert_eq!(
        TslOrigin::parse("https://example.test:443/path?query=1"),
        TslOrigin::parse("https://example.test")
    );
    assert!(TslOrigin::parse("urn:example:no-origin").is_none());
    assert!(TslOrigin::parse("https://user:password@example.test").is_none());
}

#[test]
fn rejects_pointer_byte_counter_overflow() {
    let list = parse_tsl_xml(&list_with_pointer("https://example.test/one")).unwrap();
    let context = PointerTraversalContext {
        depth: 0,
        documents_seen: 0,
        total_bytes_seen: u64::MAX,
        fetched_bytes: 1,
        fetched_media_type: TslMediaType::ApplicationXml,
        target: &list.pointers[0].url,
        ancestor_urls: &[],
    };
    assert_eq!(
        validate_pointer_traversal(&context, &policy()),
        Err(TslError::PointerPolicy(TslPointerPolicyFailure::TotalBytes))
    );
}
