// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(missing_docs, clippy::unwrap_used)]

use identity_trust_tsl_core::{
    parse_tsl_xml, validate_tsl_freshness, validate_tsl_sequence_number,
    AdditionalServiceInformationKind, QualificationCriterion, ServiceDigitalIdentity,
    TrustServiceStatus, TrustServiceType, TslAddressContext, TslAddressFailure, TslError,
    TslMediaType, TslPointerQualifierFailure, TslQualificationFailure, TslRequiredField,
    TslResourceLimit, TslStructureFailure, TslVersion, TslXmlFailure,
};

fn certificate_base64() -> String {
    include_str!("../../tsl-openssl/tests/fixtures/cert.pem")
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect()
}

fn second_certificate_base64() -> String {
    include_str!("../../x509/tests/fixtures/qwac_server_auth_cert.der.b64")
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect()
}

fn ec_certificate_base64() -> &'static str {
    "MIIBxjCCAWugAwIBAgIUJV0Fzd3wdhJzwzeDPY28CTbkAQwwCgYIKoZIzj0EAwIwODELMAkGA1UEBhMCTVQxEDAOBgNVBAoMB0V4YW1wbGUxFzAVBgNVBAMMDlRTTC1FQy1GaXh0dXJlMB4XDTI2MDkxNTAyNDIxOFoXDTM2MDkxMjAyNDIxOFowODELMAkGA1UEBhMCTVQxEDAOBgNVBAoMB0V4YW1wbGUxFzAVBgNVBAMMDlRTTC1FQy1GaXh0dXJlMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEM+DaEw5/vtoqcMN6Tr+0HeuZyJcXD+3c6Adn2g13pUf9sSVMATb38N+C7eQ9OD/StqYq86UXWJjWdJBf9vpy1KNTMFEwHQYDVR0OBBYEFJ6in5EpAeJzlje7gHkKZgUmqXIDMB8GA1UdIwQYMBaAFJ6in5EpAeJzlje7gHkKZgUmqXIDMA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDSQAwRgIhAJHXfIXb2EY4qcgsAvw11G9Pe+F0fJhDTiV1VmJJC4nQAiEAzVu2E0SRSP4nkR+miVUiEyGyRdU8mRP7xdCqMgwqPxU="
}

fn document(body: &str) -> String {
    format!(
        r#"<TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#" xmlns:at="http://uri.etsi.org/02231/v2/additionaltypes#" TSLTag="http://uri.etsi.org/19612/TSLTag" Id="TSL"><SchemeInformation><TSLVersionIdentifier>6</TSLVersionIdentifier><TSLSequenceNumber>12</TSLSequenceNumber><TSLType>https://example.test/type</TSLType><SchemeOperatorName><Name xml:lang="en">Operator</Name></SchemeOperatorName><SchemeOperatorAddress><PostalAddresses><PostalAddress xml:lang="en"><StreetAddress>Test Street 1</StreetAddress><Locality>Test City</Locality><CountryName>EU</CountryName></PostalAddress></PostalAddresses><ElectronicAddress><URI xml:lang="en">mailto:trust@example.test</URI><URI xml:lang="en">https://example.test/operator</URI></ElectronicAddress></SchemeOperatorAddress><SchemeName><Name xml:lang="en">Scheme</Name></SchemeName><SchemeInformationURI><URI xml:lang="en">https://example.test/scheme</URI></SchemeInformationURI><StatusDeterminationApproach>https://example.test/status-policy</StatusDeterminationApproach><SchemeTypeCommunityRules><URI xml:lang="en">https://example.test/rules</URI></SchemeTypeCommunityRules><SchemeTerritory>EU</SchemeTerritory><PolicyOrLegalNotice><TSLPolicy xml:lang="en">https://example.test/policy</TSLPolicy></PolicyOrLegalNotice><HistoricalInformationPeriod>65535</HistoricalInformationPeriod><ListIssueDateTime>2026-01-01T00:00:00Z</ListIssueDateTime><NextUpdate><dateTime>2026-02-01T00:00:00Z</dateTime></NextUpdate></SchemeInformation>{body}</TrustServiceStatusList>"#
    )
}

fn pointer(qualifiers: &str) -> String {
    let certificate = certificate_base64();
    format!(
        r#"<PointersToOtherTSL><OtherTSLPointer><ServiceDigitalIdentities><ServiceDigitalIdentity><DigitalId><X509Certificate>{certificate}</X509Certificate></DigitalId></ServiceDigitalIdentity></ServiceDigitalIdentities><TSLLocation>https://example.test/child.xml</TSLLocation><AdditionalInformation>{qualifiers}</AdditionalInformation></OtherTSLPointer></PointersToOtherTSL>"#
    )
}

fn required_pointer_qualifiers() -> &'static str {
    r#"<OtherInformation><TSLType>https://example.test/type</TSLType></OtherInformation><OtherInformation><SchemeOperatorName><Name xml:lang="en">Child Operator</Name></SchemeOperatorName></OtherInformation><OtherInformation><SchemeTypeCommunityRules><URI xml:lang="en">https://example.test/rules</URI></SchemeTypeCommunityRules></OtherInformation><OtherInformation><SchemeTerritory>EU</SchemeTerritory></OtherInformation><OtherInformation><at:MimeType>application/vnd.etsi.tsl+xml</at:MimeType></OtherInformation>"#
}

fn document_with_pointer(qualifiers: &str) -> String {
    document("").replace(
        "<ListIssueDateTime>",
        &format!("{}<ListIssueDateTime>", pointer(qualifiers)),
    )
}

fn document_with_service_extension(extension: &str) -> String {
    let certificate = certificate_base64();
    document(&provider(&format!(
        r#"<TSPService><ServiceInformation><ServiceTypeIdentifier>https://example.test/service-type</ServiceTypeIdentifier><ServiceName><Name xml:lang="en">Service</Name></ServiceName><ServiceDigitalIdentity><DigitalId><X509Certificate>{certificate}</X509Certificate></DigitalId></ServiceDigitalIdentity><ServiceStatus>http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted</ServiceStatus><StatusStartingTime>2025-01-01T00:00:00Z</StatusStartingTime><ServiceInformationExtensions>{extension}</ServiceInformationExtensions></ServiceInformation></TSPService>"#
    )))
}

fn document_with_qualification_extension(extension: &str) -> String {
    document_with_service_extension(extension).replace(
        "https://example.test/service-type",
        "http://uri.etsi.org/TrstSvc/Svctype/CA/QC",
    )
}

fn provider(services: &str) -> String {
    format!(
        r#"<TrustServiceProviderList><TrustServiceProvider><TSPInformation><TSPName><Name xml:lang="en">Provider</Name></TSPName><TSPTradeName><Name xml:lang="en">NTRMT-C12345</Name><Name xml:lang="en">Provider Trade Name</Name></TSPTradeName><TSPAddress><PostalAddresses><PostalAddress xml:lang="en"><StreetAddress>Provider Street 1</StreetAddress><Locality>Provider City</Locality><PostalCode>1000</PostalCode><CountryName>MT</CountryName></PostalAddress></PostalAddresses><ElectronicAddress><URI xml:lang="en">mailto:provider@example.test</URI><URI xml:lang="en">https://example.test/provider</URI></ElectronicAddress></TSPAddress><TSPInformationURI><URI xml:lang="en">https://example.test/provider/information</URI></TSPInformationURI></TSPInformation><TSPServices>{services}</TSPServices></TrustServiceProvider></TrustServiceProviderList>"#
    )
}

#[test]
fn parses_typed_metadata() {
    let tsl = parse_tsl_xml(&document("")).unwrap();
    assert_eq!(tsl.version, TslVersion::V6);
    assert_eq!(tsl.sequence_number, 12);
    assert_eq!(tsl.issue_date_time.unix_seconds(), 1_767_225_600);
}

#[test]
fn rejects_controls_prohibited_in_multilingual_text() {
    let xml = document("")
        .replace(">Scheme</Name>", ">Scheme\nName</Name>")
        .replace(
            "<TSLPolicy xml:lang=\"en\">https://example.test/policy</TSLPolicy>",
            "<TSLLegalNotice xml:lang=\"en\">First line.\nSecond line.</TSLLegalNotice>",
        );
    assert_eq!(
        parse_tsl_xml(&xml).unwrap_err(),
        TslError::InvalidStructure(TslStructureFailure::MultilingualName)
    );
}

#[test]
fn normalizes_layout_whitespace_in_multilingual_legal_notices() {
    let xml = document("").replace(
        "<TSLPolicy xml:lang=\"en\">https://example.test/policy</TSLPolicy>",
        "<TSLLegalNotice xml:lang=\"en\">First line.\nSecond\tline.</TSLLegalNotice>",
    );

    assert!(parse_tsl_xml(&xml).is_ok());
}

#[test]
fn retains_multiple_official_provider_registration_identifiers() {
    let services = document_with_service_extension("");
    let multiple = services.replace(
        "<Name xml:lang=\"en\">NTRMT-C12345</Name>",
        "<Name xml:lang=\"en\">NTRMT-C12345</Name><Name xml:lang=\"en\">VATMT-12345678</Name>",
    );
    let parsed = parse_tsl_xml(&multiple).unwrap();
    assert_eq!(parsed.providers[0].registration_identifiers.len(), 2);

    let repeated_kind = multiple.replace(
        "</TSPTradeName>",
        "<Name xml:lang=\"mt\">NTRMT-C99999</Name></TSPTradeName>",
    );
    let parsed = parse_tsl_xml(&repeated_kind).unwrap();
    assert_eq!(parsed.providers[0].registration_identifiers.len(), 3);
}

#[test]
fn coalesces_a_repeated_current_public_key_for_the_same_service_type() {
    let certificate = certificate_base64();
    let service = format!(
        r#"<TSPService><ServiceInformation><ServiceTypeIdentifier>http://uri.etsi.org/TrstSvc/Svctype/CA/QC</ServiceTypeIdentifier><ServiceName><Name xml:lang="en">Service</Name></ServiceName><ServiceDigitalIdentity><DigitalId><X509Certificate>{certificate}</X509Certificate></DigitalId></ServiceDigitalIdentity><ServiceStatus>http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted</ServiceStatus><StatusStartingTime>2025-01-01T00:00:00Z</StatusStartingTime></ServiceInformation></TSPService>"#
    );
    let xml = document(&provider(&format!("{service}{service}")));

    let parsed = parse_tsl_xml(&xml).unwrap();
    assert_eq!(parsed.providers[0].services.len(), 1);
    assert_eq!(parsed.providers[0].services[0].history.len(), 0);
}

#[test]
fn enforces_current_service_identity_presence_and_representation_consistency() {
    let valid = document_with_service_extension("");
    let missing_name = valid.replace(
        "<ServiceName><Name xml:lang=\"en\">Service</Name></ServiceName>",
        "",
    );
    assert_eq!(
        parse_tsl_xml(&missing_name).unwrap_err(),
        TslError::MissingField(TslRequiredField::ServiceName)
    );

    let missing_identity = valid.replace(
        &format!(
            "<ServiceDigitalIdentity><DigitalId><X509Certificate>{}</X509Certificate></DigitalId></ServiceDigitalIdentity>",
            certificate_base64()
        ),
        "",
    );
    assert_eq!(
        parse_tsl_xml(&missing_identity).unwrap_err(),
        TslError::MissingField(TslRequiredField::ServiceDigitalIdentity)
    );

    let mismatched_ski = valid.replace(
        "</ServiceDigitalIdentity>",
        "<DigitalId><X509SKI>AQ==</X509SKI></DigitalId></ServiceDigitalIdentity>",
    );
    assert_eq!(
        parse_tsl_xml(&mismatched_ski).unwrap_err(),
        TslError::DigitalIdentity(
            identity_trust_tsl_core::TslDigitalIdentityFailure::SubjectKeyIdentifierMismatch
        )
    );

    let mismatched_key = valid.replace(
        "</ServiceDigitalIdentity>",
        r#"<DigitalId><ds:KeyValue xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:RSAKeyValue><ds:Modulus>AQ==</ds:Modulus><ds:Exponent>Aw==</ds:Exponent></ds:RSAKeyValue></ds:KeyValue></DigitalId></ServiceDigitalIdentity>"#,
    );
    assert_eq!(
        parse_tsl_xml(&mismatched_key).unwrap_err(),
        TslError::DigitalIdentity(
            identity_trust_tsl_core::TslDigitalIdentityFailure::PublicKeyMismatch
        )
    );

    let mismatched_certificate = valid.replace(
        "</ServiceDigitalIdentity>",
        &format!(
            "<DigitalId><X509Certificate>{}</X509Certificate></DigitalId></ServiceDigitalIdentity>",
            second_certificate_base64()
        ),
    );
    assert!(matches!(
        parse_tsl_xml(&mismatched_certificate),
        Err(TslError::DigitalIdentity(
            identity_trust_tsl_core::TslDigitalIdentityFailure::PublicKeyMismatch
                | identity_trust_tsl_core::TslDigitalIdentityFailure::SubjectNameMismatch
        ))
    ));
}

#[test]
fn validates_xml_signature_11_ec_key_value_against_the_certificate() {
    let ec_key_value = r#"<DigitalId><ds:KeyValue xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><dsig11:ECKeyValue xmlns:dsig11="http://www.w3.org/2009/xmldsig11#"><dsig11:NamedCurve URI="urn:oid:1.2.840.10045.3.1.7"/><dsig11:PublicKey>BDPg2hMOf77aKnDDek6/tB3rmciXFw/t3OgHZ9oNd6VH/bElTAE29/Dfgu3kPTg/0ramKvOlF1iY1nSQX/b6ctQ=</dsig11:PublicKey></dsig11:ECKeyValue></ds:KeyValue></DigitalId>"#;
    let xml = document_with_service_extension("")
        .replace(&certificate_base64(), ec_certificate_base64())
        .replace(
            "</ServiceDigitalIdentity>",
            &format!("{ec_key_value}</ServiceDigitalIdentity>"),
        );
    assert!(parse_tsl_xml(&xml).is_ok());

    let wrong_curve = xml.replace("urn:oid:1.2.840.10045.3.1.7", "urn:oid:1.3.132.0.34");
    assert_eq!(
        parse_tsl_xml(&wrong_curve).unwrap_err(),
        TslError::DigitalIdentity(
            identity_trust_tsl_core::TslDigitalIdentityFailure::PublicKeyMismatch
        )
    );

    let wrong_point = xml.replace("BDPg2hMOf77aKnDD", "BAPg2hMOf77aKnDD");
    assert_eq!(
        parse_tsl_xml(&wrong_point).unwrap_err(),
        TslError::DigitalIdentity(
            identity_trust_tsl_core::TslDigitalIdentityFailure::PublicKeyMismatch
        )
    );
}

#[test]
fn enforces_history_ski_without_a_certificate() {
    let current_certificate = certificate_base64();
    let current = format!(
        r#"<TSPService><ServiceInformation><ServiceTypeIdentifier>https://future.example/type</ServiceTypeIdentifier><ServiceName><Name xml:lang="en">Service</Name></ServiceName><ServiceDigitalIdentity><DigitalId><X509Certificate>{current_certificate}</X509Certificate></DigitalId></ServiceDigitalIdentity><ServiceStatus>http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted</ServiceStatus><StatusStartingTime>2025-01-01T00:00:00Z</StatusStartingTime></ServiceInformation><ServiceHistory><ServiceHistoryInstance><ServiceTypeIdentifier>https://future.example/type</ServiceTypeIdentifier><ServiceName><Name xml:lang="en">Historical service</Name></ServiceName><ServiceDigitalIdentity><DigitalId><X509SKI>PxWGGXCj+NKIUPe/FVOiS18mojA=</X509SKI></DigitalId></ServiceDigitalIdentity><ServiceStatus>http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/withdrawn</ServiceStatus><StatusStartingTime>2024-01-01T00:00:00Z</StatusStartingTime></ServiceHistoryInstance></ServiceHistory></TSPService>"#
    );
    let valid = document(&provider(&current));
    assert!(parse_tsl_xml(&valid).is_ok());

    let missing_ski = valid.replace(
        "<DigitalId><X509SKI>PxWGGXCj+NKIUPe/FVOiS18mojA=</X509SKI></DigitalId>",
        "<DigitalId><X509SubjectName>O=Historical</X509SubjectName></DigitalId>",
    );
    let parsed = parse_tsl_xml(&missing_ski).unwrap();
    // An unidentifiable row is retained as a non-authorizing barrier so that
    // an older granted row cannot govern the interval it closes.
    assert_eq!(parsed.providers[0].services[0].history.len(), 1);
    assert!(parsed.providers[0].services[0].history[0]
        .digital_identity
        .is_none());

    let historical_certificate = valid.replace(
        "<DigitalId><X509SKI>PxWGGXCj+NKIUPe/FVOiS18mojA=</X509SKI></DigitalId>",
        &format!(
            "<DigitalId><X509SKI>PxWGGXCj+NKIUPe/FVOiS18mojA=</X509SKI></DigitalId><DigitalId><X509Certificate>{current_certificate}</X509Certificate></DigitalId>"
        ),
    );
    let parsed = parse_tsl_xml(&historical_certificate).unwrap();
    let historical_identity = parsed.providers[0].services[0].history[0]
        .digital_identity
        .as_ref()
        .unwrap();
    assert!(historical_identity.certificates_der().is_empty());
    assert_eq!(
        historical_identity.subject_key_identifier(),
        Some(
            &[
                63, 21, 134, 25, 112, 163, 248, 210, 136, 80, 247, 191, 21, 83, 162, 75, 95, 38,
                162, 48
            ][..]
        )
    );
}

#[test]
fn retains_future_current_state_and_every_history_row_without_projection() {
    let current_certificate = certificate_base64();
    let service = format!(
        r#"<TSPService><ServiceInformation><ServiceTypeIdentifier>https://future.example/type</ServiceTypeIdentifier><ServiceName><Name xml:lang="en">Future service</Name></ServiceName><ServiceDigitalIdentity><DigitalId><X509Certificate>{current_certificate}</X509Certificate></DigitalId></ServiceDigitalIdentity><ServiceStatus>http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted</ServiceStatus><StatusStartingTime>2027-01-01T00:00:00Z</StatusStartingTime><ServiceSupplyPoints><ServiceSupplyPoint>https://future.example/status</ServiceSupplyPoint></ServiceSupplyPoints></ServiceInformation><ServiceHistory><ServiceHistoryInstance><ServiceTypeIdentifier>https://future.example/type</ServiceTypeIdentifier><ServiceName><Name xml:lang="en">Effective service</Name></ServiceName><ServiceDigitalIdentity><DigitalId><X509SKI>PxWGGXCj+NKIUPe/FVOiS18mojA=</X509SKI></DigitalId></ServiceDigitalIdentity><ServiceStatus>http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/withdrawn</ServiceStatus><StatusStartingTime>2024-01-01T00:00:00Z</StatusStartingTime></ServiceHistoryInstance><ServiceHistoryInstance><ServiceTypeIdentifier>https://future.example/other-type</ServiceTypeIdentifier><ServiceName><Name xml:lang="en">Other type</Name></ServiceName><ServiceDigitalIdentity><DigitalId><X509SKI>PxWGGXCj+NKIUPe/FVOiS18mojA=</X509SKI></DigitalId></ServiceDigitalIdentity><ServiceStatus>http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted</ServiceStatus><StatusStartingTime>2023-01-01T00:00:00Z</StatusStartingTime></ServiceHistoryInstance></ServiceHistory></TSPService>"#
    );
    let list = parse_tsl_xml(&document(&provider(&service))).unwrap();

    // Parsing is non-destructive: the pre-published current state, its
    // supply points, and every history row (including a row of a different
    // service type) remain available for time-aware authorization.
    let service = &list.providers[0].services[0];
    assert_eq!(service.status, TrustServiceStatus::Granted);
    assert_eq!(service.status_starting_time.unix_seconds(), 1_798_761_600);
    assert_eq!(service.supply_points.len(), 1);
    assert_eq!(service.history.len(), 2);
    assert_eq!(service.history[0].status, TrustServiceStatus::Withdrawn);
    assert!(matches!(
        service.history[1].service_type,
        TrustServiceType::Other(_)
    ));
    assert_ne!(
        service.history[0].service_type,
        service.history[1].service_type
    );
}

#[test]
fn conflicting_history_rows_at_one_starting_time_become_a_barrier() {
    let current_certificate = certificate_base64();
    let row = |status: &str| {
        format!(
            r#"<ServiceHistoryInstance><ServiceTypeIdentifier>https://future.example/type</ServiceTypeIdentifier><ServiceName><Name xml:lang="en">Historical</Name></ServiceName><ServiceDigitalIdentity><DigitalId><X509SKI>PxWGGXCj+NKIUPe/FVOiS18mojA=</X509SKI></DigitalId></ServiceDigitalIdentity><ServiceStatus>http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/{status}</ServiceStatus><StatusStartingTime>2024-01-01T00:00:00Z</StatusStartingTime></ServiceHistoryInstance>"#
        )
    };
    let service = format!(
        r#"<TSPService><ServiceInformation><ServiceTypeIdentifier>https://future.example/type</ServiceTypeIdentifier><ServiceName><Name xml:lang="en">Service</Name></ServiceName><ServiceDigitalIdentity><DigitalId><X509Certificate>{current_certificate}</X509Certificate></DigitalId></ServiceDigitalIdentity><ServiceStatus>http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted</ServiceStatus><StatusStartingTime>2025-01-01T00:00:00Z</StatusStartingTime></ServiceInformation><ServiceHistory>{}{}</ServiceHistory></TSPService>"#,
        row("granted"),
        row("withdrawn")
    );
    let list = parse_tsl_xml(&document(&provider(&service))).unwrap();
    let history = &list.providers[0].services[0].history;
    assert_eq!(history.len(), 1);
    assert!(history[0].digital_identity.is_none());
}

#[test]
fn older_duplicate_service_state_does_not_widen_the_current_state() {
    let certificate = certificate_base64();
    let qualification = r#"<ServiceInformationExtensions><Extension Critical="true"><q:Qualifications xmlns:q="http://uri.etsi.org/TrstSvc/SvcInfoExt/eSigDir-1999-93-EC-TrustedList/#"><q:QualificationElement><q:Qualifiers><q:Qualifier uri="http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCWithQSCD"/></q:Qualifiers><q:CriteriaList assert="all"><q:KeyUsage><q:KeyUsageBit name="digitalSignature">true</q:KeyUsageBit></q:KeyUsage></q:CriteriaList></q:QualificationElement></q:Qualifications></Extension></ServiceInformationExtensions>"#;
    let service = |start: &str, extensions: &str, supply: &str| {
        format!(
            r#"<TSPService><ServiceInformation><ServiceTypeIdentifier>http://uri.etsi.org/TrstSvc/Svctype/CA/QC</ServiceTypeIdentifier><ServiceName><Name xml:lang="en">Service {start}</Name></ServiceName><ServiceDigitalIdentity><DigitalId><X509Certificate>{certificate}</X509Certificate></DigitalId></ServiceDigitalIdentity><ServiceStatus>http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted</ServiceStatus><StatusStartingTime>{start}</StatusStartingTime>{supply}{extensions}</ServiceInformation></TSPService>"#
        )
    };
    let older = service(
        "2024-01-01T00:00:00Z",
        qualification,
        "<ServiceSupplyPoints><ServiceSupplyPoint>https://old.example/status</ServiceSupplyPoint></ServiceSupplyPoints>",
    );
    let newer = service("2025-01-01T00:00:00Z", "", "");
    for body in [format!("{older}{newer}"), format!("{newer}{older}")] {
        let list = parse_tsl_xml(&document(&provider(&body))).unwrap();
        let service = &list.providers[0].services[0];
        assert_eq!(list.providers[0].services.len(), 1);
        assert_eq!(service.status_starting_time.unix_seconds(), 1_735_689_600);
        assert!(service.qualifications.is_empty());
        assert!(service.supply_points.is_empty());
        assert_eq!(service.service_names.len(), 1);
        assert_eq!(service.history.len(), 1);
        assert_eq!(service.history[0].qualifications.len(), 1);
        assert_eq!(
            service.history[0].status_starting_time.unix_seconds(),
            1_704_067_200
        );
    }
}

#[test]
fn rejects_unrecognized_qualification_criteria_in_noncritical_extensions() {
    let criteria = |inner: &str| {
        format!(
            r#"<Extension Critical="false"><q:Qualifications xmlns:q="http://uri.etsi.org/TrstSvc/SvcInfoExt/eSigDir-1999-93-EC-TrustedList/#" xmlns:xades="http://uri.etsi.org/01903/v1.3.2#" xmlns:future="https://future.example/criteria"><q:QualificationElement><q:Qualifiers><q:Qualifier uri="http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCWithQSCD"/></q:Qualifiers><q:CriteriaList assert="all"><q:KeyUsage><q:KeyUsageBit name="digitalSignature">true</q:KeyUsageBit></q:KeyUsage>{inner}</q:CriteriaList></q:QualificationElement></q:Qualifications></Extension>"#
        )
    };
    let known = criteria("");
    assert!(parse_tsl_xml(&document_with_qualification_extension(&known)).is_ok());

    for inner in [
        "<q:FutureCriterion/>",
        "<future:Criterion>value</future:Criterion>",
        "<q:otherCriteriaList><future:Criterion/></q:otherCriteriaList>",
        "<q:otherCriteriaList><at:FutureCriterion><at:KeyPurposeId><xades:Identifier>1.2.3</xades:Identifier></at:KeyPurposeId></at:FutureCriterion></q:otherCriteriaList>",
        // A known element in the wrong position is also not processed by the
        // typed projection and must not be silently discarded.
        "<at:ExtendedKeyUsage><at:KeyPurposeId><xades:Identifier>1.2.3</xades:Identifier></at:KeyPurposeId></at:ExtendedKeyUsage>",
        "<q:KeyUsageBit name=\"nonRepudiation\">true</q:KeyUsageBit>",
    ] {
        let extension = criteria(inner);
        assert_eq!(
            parse_tsl_xml(&document_with_qualification_extension(&extension)).unwrap_err(),
            TslError::Qualification(TslQualificationFailure::UnsupportedSemantics),
            "{inner}"
        );
        let critical = extension.replace("Critical=\"false\"", "Critical=\"true\"");
        // Inside a critical extension a foreign-namespace element is already
        // rejected by the namespace boundary; both outcomes are typed.
        assert!(
            matches!(
                parse_tsl_xml(&document_with_qualification_extension(&critical)).unwrap_err(),
                TslError::UnsupportedCriticalExtension
                    | TslError::Xml(TslXmlFailure::ElementNamespace)
            ),
            "{inner}"
        );
    }
}

#[test]
fn rejects_future_issue_time_and_sequence_rollback() {
    let list = parse_tsl_xml(&document("")).unwrap();
    // ListIssueDateTime is 2026-01-01T00:00:00Z (1_767_225_600).
    let within_skew = time::OffsetDateTime::from_unix_timestamp(1_767_225_600 - 300).unwrap();
    let beyond_skew = time::OffsetDateTime::from_unix_timestamp(1_767_225_600 - 301).unwrap();
    assert!(validate_tsl_freshness(&list, within_skew).is_ok());
    assert_eq!(
        validate_tsl_freshness(&list, beyond_skew).unwrap_err(),
        TslError::NotYetIssued
    );

    // The fixture carries TSLSequenceNumber 12.
    assert!(validate_tsl_sequence_number(&list, 12).is_ok());
    assert!(validate_tsl_sequence_number(&list, 11).is_ok());
    assert_eq!(
        validate_tsl_sequence_number(&list, 13).unwrap_err(),
        TslError::SequenceRollback
    );
}

#[test]
fn separates_pki_and_non_pki_service_identity_forms() {
    let valid = document_with_service_extension("");
    let mixed = valid.replace(
        "</ServiceDigitalIdentity>",
        "<DigitalId><Other>https://example.test/non-pki-id</Other></DigitalId></ServiceDigitalIdentity>",
    );
    let parsed = parse_tsl_xml(&mixed).unwrap();
    assert!(matches!(
        parsed.providers[0].services[0].digital_identity,
        ServiceDigitalIdentity::Pki(_)
    ));

    let non_pki = valid
        .replace(
            "https://example.test/service-type",
            "http://uri.etsi.org/TrstSvc/Svctype/Archiv/nothavingPKIid",
        )
        .replace(
            &format!(
                "<DigitalId><X509Certificate>{}</X509Certificate></DigitalId>",
                certificate_base64()
            ),
            "<DigitalId><Other>https://example.test/non-pki-id</Other></DigitalId>",
        );
    assert!(matches!(
        parse_tsl_xml(&non_pki)
            .unwrap()
            .services()
            .next()
            .unwrap()
            .digital_identity,
        ServiceDigitalIdentity::NonPki(_)
    ));
}

#[test]
fn rejects_noncanonical_tsl_tag() {
    let wrong_tag = document("").replace(
        "TSLTag=\"http://uri.etsi.org/19612/TSLTag\"",
        "TSLTag=\"https://example.test/tag\"",
    );
    assert_eq!(parse_tsl_xml(&wrong_tag).unwrap_err(), TslError::InvalidTag);

    let missing_tag = document("").replace(" TSLTag=\"http://uri.etsi.org/19612/TSLTag\"", "");
    assert_eq!(
        parse_tsl_xml(&missing_tag).unwrap_err(),
        TslError::MissingField(TslRequiredField::Tag)
    );
}

#[test]
fn enforces_the_six_calendar_month_next_update_window() {
    let backward = document("").replace(
        "<dateTime>2026-02-01T00:00:00Z</dateTime>",
        "<dateTime>2025-12-31T23:59:59Z</dateTime>",
    );
    let over_six_months = document("").replace(
        "<dateTime>2026-02-01T00:00:00Z</dateTime>",
        "<dateTime>2026-07-01T01:00:01Z</dateTime>",
    );
    for xml in [backward, over_six_months] {
        assert_eq!(
            parse_tsl_xml(&xml).unwrap_err(),
            TslError::InvalidUpdateWindow
        );
    }

    let month_end = document("")
        .replace("2026-01-01T00:00:00Z", "2026-01-31T00:00:00Z")
        .replace("2026-02-01T00:00:00Z", "2026-07-31T00:00:00Z");
    assert!(parse_tsl_xml(&month_end).is_ok());

    let dst_shifted = month_end.replace("2026-07-31T00:00:00Z", "2026-07-31T01:00:00Z");
    assert!(parse_tsl_xml(&dst_shifted).is_ok());

    let after_month_end = month_end.replace("2026-07-31T00:00:00Z", "2026-07-31T01:00:01Z");
    assert_eq!(
        parse_tsl_xml(&after_month_end).unwrap_err(),
        TslError::InvalidUpdateWindow
    );
}

#[test]
fn discards_an_expired_list_at_the_caller_selected_time() {
    let list = parse_tsl_xml(&document("")).unwrap();
    let before_deadline = time::OffsetDateTime::from_unix_timestamp(1_769_903_999).unwrap();
    let at_deadline = time::OffsetDateTime::from_unix_timestamp(1_769_904_000).unwrap();

    assert!(validate_tsl_freshness(&list, before_deadline).is_ok());
    assert_eq!(
        validate_tsl_freshness(&list, at_deadline).unwrap_err(),
        TslError::Expired
    );
}

#[test]
fn projects_every_normative_pointer_qualifier_and_issuer_identity() {
    let parsed = parse_tsl_xml(&document_with_pointer(required_pointer_qualifiers())).unwrap();
    let projected = &parsed.pointers[0];
    assert_eq!(projected.digital_identities.len(), 1);
    assert_eq!(projected.certificates_der().count(), 1);
    assert_eq!(projected.tsl_type.as_str(), "https://example.test/type");
    assert_eq!(projected.scheme_operator_names[0].value, "Child Operator");
    assert_eq!(
        projected.scheme_type_community_rules[0].uri.as_str(),
        "https://example.test/rules"
    );
    assert_eq!(projected.territory, "EU");
    assert_eq!(projected.media_type, TslMediaType::EtsiTrustedListXml);
}

#[test]
fn preserves_pointer_identity_grouping_and_bounds_issuer_rotation_sets() {
    let certificate = certificate_base64();
    let grouped = pointer(required_pointer_qualifiers()).replace(
        "</ServiceDigitalIdentities>",
        &format!(
            "<ServiceDigitalIdentity><DigitalId><X509Certificate>{certificate}</X509Certificate></DigitalId><DigitalId><X509SKI>PxWGGXCj+NKIUPe/FVOiS18mojA=</X509SKI></DigitalId></ServiceDigitalIdentity></ServiceDigitalIdentities>"
        ),
    );
    let parsed = parse_tsl_xml(&document("").replace(
        "<ListIssueDateTime>",
        &format!("{grouped}<ListIssueDateTime>"),
    ))
    .unwrap();
    assert_eq!(parsed.pointers[0].digital_identities.len(), 2);
    assert_eq!(parsed.pointers[0].certificates_der().count(), 2);

    let identity = format!(
        "<ServiceDigitalIdentity><DigitalId><X509Certificate>{certificate}</X509Certificate></DigitalId></ServiceDigitalIdentity>"
    );
    let excessive = pointer(required_pointer_qualifiers()).replace(&identity, &identity.repeat(65));
    assert_eq!(
        parse_tsl_xml(&document("").replace(
            "<ListIssueDateTime>",
            &format!("{excessive}<ListIssueDateTime>"),
        ))
        .unwrap_err(),
        TslError::ResourceLimit(TslResourceLimit::PointerIdentities)
    );
}

#[test]
fn rejects_missing_duplicate_and_contradictory_pointer_qualifiers() {
    let missing = required_pointer_qualifiers().replace(
        "<OtherInformation><SchemeTerritory>EU</SchemeTerritory></OtherInformation>",
        "",
    );
    assert_eq!(
        parse_tsl_xml(&document_with_pointer(&missing)).unwrap_err(),
        TslError::PointerQualifier(TslPointerQualifierFailure::Missing)
    );

    let duplicate = format!(
        "{}<OtherInformation><SchemeTerritory>EU</SchemeTerritory></OtherInformation>",
        required_pointer_qualifiers()
    );
    assert_eq!(
        parse_tsl_xml(&document_with_pointer(&duplicate)).unwrap_err(),
        TslError::PointerQualifier(TslPointerQualifierFailure::Duplicate)
    );

    let contradictory = format!(
        "{}<OtherInformation><SchemeTerritory>US</SchemeTerritory></OtherInformation>",
        required_pointer_qualifiers()
    );
    assert_eq!(
        parse_tsl_xml(&document_with_pointer(&contradictory)).unwrap_err(),
        TslError::PointerQualifier(TslPointerQualifierFailure::Contradictory)
    );
}

#[test]
fn rejects_malformed_pointer_qualifier_and_missing_issuer_identity() {
    let malformed = required_pointer_qualifiers().replace(
        "<TSLType>https://example.test/type</TSLType>",
        "<TSLType>https://example.test/type</TSLType><SchemeTerritory>EU</SchemeTerritory>",
    );
    assert_eq!(
        parse_tsl_xml(&document_with_pointer(&malformed)).unwrap_err(),
        TslError::PointerQualifier(TslPointerQualifierFailure::Malformed)
    );

    let no_identity = pointer(required_pointer_qualifiers()).replace(
        &format!("<ServiceDigitalIdentities><ServiceDigitalIdentity><DigitalId><X509Certificate>{}</X509Certificate></DigitalId></ServiceDigitalIdentity></ServiceDigitalIdentities>", certificate_base64()),
        "",
    );
    assert_eq!(
        parse_tsl_xml(&document("").replace(
            "<ListIssueDateTime>",
            &format!("{no_identity}<ListIssueDateTime>"),
        ))
        .unwrap_err(),
        TslError::PointerQualifier(TslPointerQualifierFailure::MissingIssuerIdentity)
    );
}

#[test]
fn accepts_profile_pdf_and_rejects_unsupported_pointer_mime_types() {
    let pdf =
        required_pointer_qualifiers().replace("application/vnd.etsi.tsl+xml", "application/pdf");
    let parsed = parse_tsl_xml(&document_with_pointer(&pdf)).unwrap();
    assert_eq!(parsed.pointers[0].media_type, TslMediaType::Pdf);

    for mime_type in ["application/xml", "text/xml", "application/json"] {
        let qualifiers =
            required_pointer_qualifiers().replace("application/vnd.etsi.tsl+xml", mime_type);
        assert_eq!(
            parse_tsl_xml(&document_with_pointer(&qualifiers)).unwrap_err(),
            TslError::PointerQualifier(TslPointerQualifierFailure::NonNormativeMimeType),
        );
    }
}

#[test]
fn parses_service_and_history_without_erasing_unknown_uris() {
    let body = provider(&format!(
        r#"<TSPService><ServiceInformation><ServiceTypeIdentifier>https://future.example/type</ServiceTypeIdentifier><ServiceName><Name xml:lang="en">Service</Name></ServiceName><ServiceDigitalIdentity><DigitalId><X509Certificate>{}</X509Certificate></DigitalId></ServiceDigitalIdentity><ServiceStatus>http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted</ServiceStatus><StatusStartingTime>2025-01-01T00:00:00Z</StatusStartingTime></ServiceInformation><ServiceHistory><ServiceHistoryInstance><ServiceTypeIdentifier>https://future.example/type</ServiceTypeIdentifier><ServiceName><Name xml:lang="en">Service</Name></ServiceName><ServiceDigitalIdentity><DigitalId><X509SubjectName>C=MT,O=Test Scheme Operator,CN=TrustedListFixtureSigner</X509SubjectName></DigitalId><DigitalId><X509SKI>PxWGGXCj+NKIUPe/FVOiS18mojA=</X509SKI></DigitalId></ServiceDigitalIdentity><ServiceStatus>http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/withdrawn</ServiceStatus><StatusStartingTime>2024-01-01T00:00:00Z</StatusStartingTime></ServiceHistoryInstance></ServiceHistory></TSPService>"#,
        certificate_base64()
    ));
    let tsl = parse_tsl_xml(&document(&body)).unwrap();
    let service = tsl.services().next().unwrap();
    assert!(matches!(service.service_type, TrustServiceType::Other(_)));
    assert_eq!(service.status, TrustServiceStatus::Granted);
    assert_eq!(service.certificates_der().len(), 1);
    assert_eq!(service.history[0].status, TrustServiceStatus::Withdrawn);
    assert!(matches!(
        service.history[0].digital_identity,
        Some(ServiceDigitalIdentity::Pki(_))
    ));
    assert_eq!(tsl.providers[0].registration_identifiers[0].value, "C12345");
    assert_eq!(tsl.providers[0].address.electronic_addresses.len(), 2);
}

#[test]
fn rejects_namespace_spoofing_and_non_utc_time() {
    let wrong_namespace = document("").replace(
        "http://uri.etsi.org/02231/v2#",
        "https://attacker.example/tsl",
    );
    assert_eq!(
        parse_tsl_xml(&wrong_namespace).unwrap_err(),
        TslError::Xml(TslXmlFailure::Root)
    );
    let non_utc = document("").replace("2026-01-01T00:00:00Z", "2026-01-01T01:00:00+01:00");
    assert_eq!(
        parse_tsl_xml(&non_utc).unwrap_err(),
        TslError::InvalidTimestamp
    );
}

#[test]
fn rejects_foreign_namespace_elements_and_misplaced_xml_signatures() {
    let spoofed = document("")
        .replace(
            "<SchemeInformation>",
            "<evil:SchemeInformation xmlns:evil=\"https://attacker.example/ns\">",
        )
        .replace("</SchemeInformation>", "</evil:SchemeInformation>");
    assert_eq!(
        parse_tsl_xml(&spoofed).unwrap_err(),
        TslError::Xml(TslXmlFailure::ElementNamespace)
    );

    let misplaced = document(r#"<ds:SignedInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"/>"#);
    assert_eq!(
        parse_tsl_xml(&misplaced).unwrap_err(),
        TslError::Xml(TslXmlFailure::ElementNamespace)
    );
}

#[test]
fn accepts_understood_critical_additional_service_information() {
    let xml = document_with_service_extension(
        r#"<Extension Critical="1"><AdditionalServiceInformation><URI xml:lang="en">http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/ForeSignatures</URI></AdditionalServiceInformation></Extension>"#,
    );
    let parsed = parse_tsl_xml(&xml).unwrap();
    assert_eq!(
        parsed
            .services()
            .next()
            .unwrap()
            .additional_service_information[0]
            .kind,
        AdditionalServiceInformationKind::ForElectronicSignatures
    );
}

#[test]
fn rejects_unrecognized_critical_service_extensions() {
    let xml = document_with_service_extension(
        r#"<Extension Critical="true"><FutureSemantics/></Extension>"#,
    );
    assert_eq!(
        parse_tsl_xml(&xml).unwrap_err(),
        TslError::UnsupportedCriticalExtension
    );
}

#[test]
fn permits_unrecognized_noncritical_service_extensions() {
    let xml = document_with_service_extension(
        r#"<Extension Critical="false"><FutureSemantics/></Extension>"#,
    );
    let parsed = parse_tsl_xml(&xml).unwrap();
    assert!(parsed
        .services()
        .next()
        .unwrap()
        .additional_service_information
        .is_empty());
}

#[test]
fn rejects_invalid_critical_attribute_values() {
    let xml = document_with_service_extension(
        r#"<Extension Critical="yes"><AdditionalServiceInformation><URI xml:lang="en">https://example.test/service-policy</URI></AdditionalServiceInformation></Extension>"#,
    );
    assert_eq!(
        parse_tsl_xml(&xml).unwrap_err(),
        TslError::Xml(TslXmlFailure::CriticalAttribute)
    );
}

#[test]
fn rejects_unsupported_version_and_excessive_depth() {
    for unsupported in ["5", "7"] {
        let version = document("").replace(
            "<TSLVersionIdentifier>6</TSLVersionIdentifier>",
            &format!("<TSLVersionIdentifier>{unsupported}</TSLVersionIdentifier>"),
        );
        assert_eq!(
            parse_tsl_xml(&version).unwrap_err(),
            TslError::UnsupportedVersion
        );
    }
    let nested = format!("{}{}", "<x>".repeat(129), "</x>".repeat(129));
    assert_eq!(
        parse_tsl_xml(&document(&nested)).unwrap_err(),
        TslError::ResourceLimit(TslResourceLimit::XmlDepth)
    );
}

include!("tsl_parse/scheme_metadata_tests.rs");
include!("tsl_parse/qualification_edge_tests.rs");
include!("tsl_parse/etsi_119612_v2_4_1_tests.rs");
