// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#[test]
fn accepts_multilingual_electronic_address_roles_without_positional_inference() {
    let operator_address = r#"<ElectronicAddress><URI xml:lang="fr">https://example.test/fr/contact</URI><URI xml:lang="en">mailto:trust@example.test</URI><URI xml:lang="en">https://example.test/contact</URI><URI xml:lang="en">tel:+41445550100</URI></ElectronicAddress>"#;
    let provider_address = r#"<ElectronicAddress><URI xml:lang="en">https://provider.example.test/contact</URI><URI xml:lang="de">https://provider.example.test/de/kontakt</URI><URI xml:lang="en">mailto:provider@example.test</URI></ElectronicAddress>"#;
    let xml = document_with_service_extension("")
        .replace(
            r#"<ElectronicAddress><URI xml:lang="en">mailto:trust@example.test</URI><URI xml:lang="en">https://example.test/operator</URI></ElectronicAddress>"#,
            operator_address,
        )
        .replace(
            r#"<ElectronicAddress><URI xml:lang="en">mailto:provider@example.test</URI><URI xml:lang="en">https://example.test/provider</URI></ElectronicAddress>"#,
            provider_address,
        );

    let parsed = parse_tsl_xml(&xml).unwrap();
    assert_eq!(parsed.scheme_operator_address.electronic_addresses.len(), 4);
    assert_eq!(parsed.providers[0].address.electronic_addresses.len(), 3);

    let debug_output = format!("{:?}", parsed.scheme_operator_address);
    assert!(!debug_output.contains("trust@example.test"));
    assert!(!debug_output.contains("https://example.test/contact"));
}

#[test]
fn rejects_missing_or_unknown_electronic_address_roles_with_typed_context() {
    let missing_website = document("").replace(
        r#"<URI xml:lang="en">https://example.test/operator</URI>"#,
        r#"<URI xml:lang="en">tel:+41445550100</URI>"#,
    );
    assert_eq!(
        parse_tsl_xml(&missing_website).unwrap_err(),
        TslError::Address(
            TslAddressContext::SchemeOperator,
            TslAddressFailure::MissingWebsite
        )
    );

    let unsupported_provider_scheme = document_with_service_extension("").replace(
        r#"<URI xml:lang="en">https://example.test/provider</URI>"#,
        r#"<URI xml:lang="en">ftp://example.test/provider</URI>"#,
    );
    assert_eq!(
        parse_tsl_xml(&unsupported_provider_scheme).unwrap_err(),
        TslError::Address(
            TslAddressContext::Provider,
            TslAddressFailure::ElectronicScheme
        )
    );

    let empty_mailbox = document("").replace(
        "mailto:trust@example.test",
        "mailto:",
    );
    assert_eq!(
        parse_tsl_xml(&empty_mailbox).unwrap_err(),
        TslError::Address(
            TslAddressContext::SchemeOperator,
            TslAddressFailure::ElectronicUri
        )
    );

    let invalid_language = document("").replace(
        r#"<URI xml:lang="en">mailto:trust@example.test</URI>"#,
        r#"<URI xml:lang="EN">mailto:trust@example.test</URI>"#,
    );
    assert_eq!(
        parse_tsl_xml(&invalid_language).unwrap_err(),
        TslError::Address(
            TslAddressContext::SchemeOperator,
            TslAddressFailure::ElectronicLanguage
        )
    );

    let malformed_language = document("").replace(
        r#"<URI xml:lang="en">mailto:trust@example.test</URI>"#,
        r#"<URI xml:lang="en-1">mailto:trust@example.test</URI>"#,
    );
    assert_eq!(
        parse_tsl_xml(&malformed_language).unwrap_err(),
        TslError::Address(
            TslAddressContext::SchemeOperator,
            TslAddressFailure::ElectronicLanguage
        )
    );
}

#[test]
fn accepts_and_normalizes_rfc5646_case_for_multilingual_pointers() {
    let xml = document("").replace(
        r#"<SchemeInformationURI><URI xml:lang="en">"#,
        r#"<SchemeInformationURI><URI xml:lang="EN">"#,
    );
    let parsed = parse_tsl_xml(&xml).unwrap();

    assert_eq!(parsed.scheme_information_uris[0].language, "en");
}

#[test]
fn normalizes_deployed_provider_metadata_compatibility_forms() {
    let invalid_information_uri = document_with_service_extension("").replace(
        "https://example.test/provider/information",
        "www.example.test/provider/information",
    );
    let parsed = parse_tsl_xml(&invalid_information_uri).unwrap();
    assert_eq!(
        parsed.providers[0].information_uris[0].uri.as_str(),
        "https://www.example.test/provider/information"
    );

    let missing_trade_name = document_with_service_extension("").replace(
        "<TSPTradeName><Name xml:lang=\"en\">NTRMT-C12345</Name><Name xml:lang=\"en\">Provider Trade Name</Name></TSPTradeName>",
        "",
    );
    let parsed = parse_tsl_xml(&missing_trade_name).unwrap();
    assert_eq!(parsed.providers[0].trade_names, parsed.providers[0].names);
}

#[test]
fn accepts_noncritical_extension_subtrees_and_understood_taken_over_by() {
    let future_extension = document_with_service_extension(
        r#"<Extension Critical="false"><future:Semantics xmlns:future="https://future.example/schema"><future:Nested/></future:Semantics></Extension>"#,
    );
    assert!(parse_tsl_xml(&future_extension).is_ok());

    let taken_over_by = document_with_service_extension(
        r#"<Extension Critical="true"><at:TakenOverBy><at:URI xml:lang="en">https://example.test/takeover</at:URI><at:TSPName><Name xml:lang="en">Successor Provider</Name></at:TSPName><SchemeOperatorName><Name xml:lang="en">Operator</Name></SchemeOperatorName><SchemeTerritory>EU</SchemeTerritory></at:TakenOverBy></Extension>"#,
    );
    assert!(parse_tsl_xml(&taken_over_by).is_ok());

    let incomplete = taken_over_by.replace(
        "<SchemeTerritory>EU</SchemeTerritory></at:TakenOverBy>",
        "</at:TakenOverBy>",
    );
    assert_eq!(
        parse_tsl_xml(&incomplete).unwrap_err(),
        TslError::InvalidStructure(TslStructureFailure::Extension)
    );
}

#[test]
fn normalizes_xades_object_identifier_forms_and_rejects_non_oid_policies() {
    let extension = r#"<Extension Critical="true"><q:Qualifications xmlns:q="http://uri.etsi.org/TrstSvc/SvcInfoExt/eSigDir-1999-93-EC-TrustedList/#" xmlns:xades="http://uri.etsi.org/01903/v1.3.2#"><q:QualificationElement><q:Qualifiers><q:Qualifier uri="http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCWithQSCD"/></q:Qualifiers><q:CriteriaList assert="all"><q:PolicySet><q:PolicyIdentifier><xades:Identifier Qualifier="OIDAsURN">urn:oid:1.2.3.4</xades:Identifier><xades:Description/><xades:DocumentationReferences><xades:DocumentationReference>https://example.test/policy</xades:DocumentationReference></xades:DocumentationReferences></q:PolicyIdentifier><q:PolicyIdentifier><xades:Identifier Qualifier="OIDAsURI">oid:1.2.3.5</xades:Identifier></q:PolicyIdentifier><q:PolicyIdentifier><xades:Identifier>1.2.3.6</xades:Identifier></q:PolicyIdentifier></q:PolicySet></q:CriteriaList></q:QualificationElement></q:Qualifications></Extension>"#;
    let parsed = parse_tsl_xml(&document_with_qualification_extension(extension)).unwrap();
    let qualification = &parsed.services().next().unwrap().qualifications[0];
    assert!(matches!(
        qualification.criteria.criteria[0],
        QualificationCriterion::CertificatePolicies(_)
    ));
    let QualificationCriterion::CertificatePolicies(policies) =
        &qualification.criteria.criteria[0]
    else {
        return;
    };
    assert_eq!(policies.len(), 3);
    assert_eq!(policies[0].as_str(), "1.2.3.4");
    assert_eq!(policies[1].as_str(), "1.2.3.5");
    assert_eq!(policies[2].as_str(), "1.2.3.6");

    let non_oid = extension.replace("urn:oid:1.2.3.4", "https://example.test/policy-id");
    assert_eq!(
        parse_tsl_xml(&document_with_qualification_extension(&non_oid)).unwrap_err(),
        TslError::Qualification(TslQualificationFailure::PolicyIdentifier)
    );
}

#[test]
fn handles_unusable_history_and_opaque_non_pki_identifier_forms() {
    let service = r#"<TSPService><ServiceInformation><ServiceTypeIdentifier>https://example.test/service/nothavingPKIid</ServiceTypeIdentifier><ServiceName><Name xml:lang="en">Service</Name></ServiceName><ServiceDigitalIdentity><DigitalId><Other>https://example.test/current</Other></DigitalId></ServiceDigitalIdentity><ServiceStatus>http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted</ServiceStatus><StatusStartingTime>2025-01-01T00:00:00Z</StatusStartingTime></ServiceInformation><ServiceHistory><ServiceHistoryInstance><ServiceTypeIdentifier>https://example.test/service/nothavingPKIid</ServiceTypeIdentifier><ServiceName><Name xml:lang="en">Historical service</Name></ServiceName><ServiceDigitalIdentity><DigitalId><Other>https://example.test/historical</Other></DigitalId></ServiceDigitalIdentity><ServiceStatus>http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/withdrawn</ServiceStatus><StatusStartingTime>2024-01-01T00:00:00Z</StatusStartingTime></ServiceHistoryInstance></ServiceHistory></TSPService>"#.to_owned();
    let parsed = parse_tsl_xml(&document(&provider(&service))).unwrap();
    // The unidentifiable row cannot authorize, but it is kept as a barrier
    // that closes the interval of any older row.
    assert_eq!(parsed.providers[0].services[0].history.len(), 1);
    assert!(parsed.providers[0].services[0].history[0]
        .digital_identity
        .is_none());

    let complex_other = document(&provider(&service.replace(
        "<Other>https://example.test/current</Other>",
        r#"<Other><future:Identifier xmlns:future="https://future.example/schema">value</future:Identifier></Other>"#,
    )));
    assert_eq!(
        parse_tsl_xml(&complex_other).unwrap_err(),
        TslError::DigitalIdentity(identity_trust_tsl_core::TslDigitalIdentityFailure::MissingCertificate)
    );

    let opaque_non_pki_identifier = document(&provider(&service.replace(
        "https://example.test/current",
        "https://example.test/path with spaces",
    )));
    let parsed = parse_tsl_xml(&opaque_non_pki_identifier).unwrap();
    let identity = &parsed.providers[0].services[0].digital_identity;
    assert!(matches!(identity, ServiceDigitalIdentity::NonPki(_)));
    if let ServiceDigitalIdentity::NonPki(identifier) = identity {
        assert_eq!(identifier.as_str(), "https://example.test/path with spaces");
    }
}

#[test]
fn redacts_current_non_pki_identity_from_debug_output() {
    let service = r#"<TSPService><ServiceInformation><ServiceTypeIdentifier>https://example.test/service/nothavingPKIid</ServiceTypeIdentifier><ServiceName><Name xml:lang="en">Service</Name></ServiceName><ServiceDigitalIdentity><DigitalId><Other>https://identifier.example.test/private</Other></DigitalId></ServiceDigitalIdentity><ServiceStatus>http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted</ServiceStatus><StatusStartingTime>2025-01-01T00:00:00Z</StatusStartingTime></ServiceInformation></TSPService>"#;
    let parsed = parse_tsl_xml(&document(&provider(service))).unwrap();
    let debug_output = format!("{:?}", parsed.services().next().unwrap().digital_identity);

    assert_eq!(
        debug_output,
        "ServiceDigitalIdentity::NonPki(<redacted>)"
    );
    assert!(!debug_output.contains("identifier.example.test"));
}

#[test]
fn live_v6_audit_manifest_covers_every_selected_territory_once() {
    let manifest = include_str!("../fixtures/live-v6/manifest.tsv");
    let mut territories = Vec::new();
    for line in manifest.lines().filter(|line| !line.starts_with('#')) {
        let columns: Vec<_> = line.split('\t').collect();
        let territory = columns.first().copied().unwrap_or_default();
        assert_eq!(territory.len(), 2);
        assert_eq!(columns.get(3), Some(&"accepted"));
        assert!(!territories.contains(&territory));
        territories.push(territory);
    }
    territories.sort_unstable();
    assert_eq!(
        territories,
        [
            "AT", "BE", "BG", "CY", "CZ", "DE", "DK", "EE", "EL", "ES", "FI", "FR", "HR",
            "HU", "IE", "IS", "IT", "LI", "LT", "LU", "LV", "MT", "NL", "NO", "PL", "PT",
            "RO", "SE", "SI", "SK", "UK",
        ]
    );
}
