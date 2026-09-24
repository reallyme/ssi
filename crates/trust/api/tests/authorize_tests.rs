// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::print_stderr
)]
//! Tests for TSL-based trust authorization.

use identity_credential_trust_api::{authorize_issuer, AuthorizationPurpose};

use envelopes_x509::model::X509Certificate;
use envelopes_x509::CertificatePolicyId;
use identity_trust_tsl_core::{parse_tsl_xml, TrustedList};
use reallyme_trust_core::{
    TrustDecision, TrustEvidence, TrustOutcome, TrustPolicyId, TrustPurpose,
};

fn dummy_cert() -> X509Certificate {
    envelopes_x509::parse_cert_pem(
        include_bytes!("../../tsl-openssl/tests/fixtures/cert.pem").as_slice(),
    )
    .unwrap()
}

fn certificate_base64() -> String {
    include_str!("../../tsl-openssl/tests/fixtures/cert.pem")
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect()
}

fn provider(services: &str) -> String {
    format!(
        r#"<TrustServiceProviderList><TrustServiceProvider><TSPInformation><TSPName><Name xml:lang="en">Provider</Name></TSPName><TSPTradeName><Name xml:lang="en">NTRMT-C12345</Name></TSPTradeName><TSPAddress><PostalAddresses><PostalAddress xml:lang="en"><StreetAddress>Provider Street 1</StreetAddress><Locality>Provider City</Locality><PostalCode>1000</PostalCode><CountryName>MT</CountryName></PostalAddress></PostalAddresses><ElectronicAddress><URI xml:lang="en">mailto:provider@example.test</URI><URI xml:lang="en">https://example.test/provider</URI></ElectronicAddress></TSPAddress><TSPInformationURI><URI xml:lang="en">https://example.test/provider/information</URI></TSPInformationURI></TSPInformation><TSPServices>{services}</TSPServices></TrustServiceProvider></TrustServiceProviderList>"#
    )
}

fn trusted_decision_at(cert: X509Certificate, evaluated_at_unix_seconds: i64) -> TrustDecision {
    TrustDecision {
        outcome: TrustOutcome::Trusted,
        accepted: true,
        chain: Some(envelopes_x509::X509Chain { certs: vec![cert] }),
        failures: vec![],
        evidence: TrustEvidence {
            purpose: TrustPurpose::QeaaIssuer,
            policy_id: TrustPolicyId::EuQeaaV1,
            evaluated_at: time::OffsetDateTime::from_unix_timestamp(evaluated_at_unix_seconds)
                .unwrap(),
            source: None,
            trust_anchor: None,
            certificate_status: Vec::new(),
        },
    }
}

fn trusted_decision(cert: X509Certificate) -> TrustDecision {
    trusted_decision_at(cert, 1_780_000_000)
}

fn trusted_list_document(body: &str) -> String {
    format!(
        r#"<TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#" TSLTag="http://uri.etsi.org/19612/TSLTag" Id="TSL"><SchemeInformation><TSLVersionIdentifier>6</TSLVersionIdentifier><TSLSequenceNumber>1</TSLSequenceNumber><TSLType>https://example.test/type</TSLType><SchemeOperatorName><Name xml:lang="en">Operator</Name></SchemeOperatorName><SchemeOperatorAddress><PostalAddresses><PostalAddress xml:lang="en"><StreetAddress>Test Street 1</StreetAddress><Locality>Test City</Locality><CountryName>EU</CountryName></PostalAddress></PostalAddresses><ElectronicAddress><URI xml:lang="en">mailto:trust@example.test</URI><URI xml:lang="en">https://example.test/operator</URI></ElectronicAddress></SchemeOperatorAddress><SchemeName><Name xml:lang="en">Scheme</Name></SchemeName><SchemeInformationURI><URI xml:lang="en">https://example.test/scheme</URI></SchemeInformationURI><StatusDeterminationApproach>https://example.test/status-policy</StatusDeterminationApproach><SchemeTypeCommunityRules><URI xml:lang="en">https://example.test/rules</URI></SchemeTypeCommunityRules><SchemeTerritory>EU</SchemeTerritory><PolicyOrLegalNotice><TSLPolicy xml:lang="en">https://example.test/policy</TSLPolicy></PolicyOrLegalNotice><HistoricalInformationPeriod>65535</HistoricalInformationPeriod><ListIssueDateTime>2026-01-01T00:00:00Z</ListIssueDateTime><NextUpdate><dateTime>2026-02-01T00:00:00Z</dateTime></NextUpdate></SchemeInformation>{body}</TrustServiceStatusList>"#
    )
}

fn trusted_list(service_type: &str) -> TrustedList {
    trusted_list_with_extensions(service_type, "")
}

fn trusted_list_with_extensions(service_type: &str, extensions: &str) -> TrustedList {
    let certificate = certificate_base64();
    let services = format!(
        r#"<TSPService><ServiceInformation><ServiceTypeIdentifier>{service_type}</ServiceTypeIdentifier><ServiceName><Name xml:lang="en">Service</Name></ServiceName><ServiceDigitalIdentity><DigitalId><X509Certificate>{certificate}</X509Certificate></DigitalId></ServiceDigitalIdentity><ServiceStatus>http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted</ServiceStatus><StatusStartingTime>2026-01-01T00:00:00Z</StatusStartingTime>{extensions}</ServiceInformation></TSPService>"#
    );
    let body = provider(&services);
    let xml = trusted_list_document(&body);
    parse_tsl_xml(&xml).unwrap()
}

fn qualification_extension(qualifier: &str) -> String {
    qualification_extension_with_qualifiers(&format!(r#"<sie:Qualifier uri="{qualifier}"/>"#))
}

fn qualification_extension_with_qualifiers(qualifiers: &str) -> String {
    format!(
        r#"<ServiceInformationExtensions><Extension Critical="true"><sie:Qualifications xmlns:sie="http://uri.etsi.org/TrstSvc/SvcInfoExt/eSigDir-1999-93-EC-TrustedList/#"><sie:QualificationElement><sie:Qualifiers>{qualifiers}</sie:Qualifiers><sie:CriteriaList assert="all"><sie:KeyUsage><sie:KeyUsageBit name="digitalSignature">true</sie:KeyUsageBit></sie:KeyUsage></sie:CriteriaList></sie:QualificationElement></sie:Qualifications></Extension></ServiceInformationExtensions>"#
    )
}

fn trusted_list_with_history() -> TrustedList {
    let certificate = certificate_base64();
    let services = format!(
        r#"<TSPService><ServiceInformation><ServiceTypeIdentifier>http://uri.etsi.org/TrstSvc/Svctype/EAA/Q</ServiceTypeIdentifier><ServiceName><Name xml:lang="en">Service</Name></ServiceName><ServiceDigitalIdentity><DigitalId><X509Certificate>{certificate}</X509Certificate></DigitalId></ServiceDigitalIdentity><ServiceStatus>http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/withdrawn</ServiceStatus><StatusStartingTime>2026-01-01T00:00:00Z</StatusStartingTime></ServiceInformation><ServiceHistory><ServiceHistoryInstance><ServiceTypeIdentifier>http://uri.etsi.org/TrstSvc/Svctype/EAA/Q</ServiceTypeIdentifier><ServiceName><Name xml:lang="en">Historical service</Name></ServiceName><ServiceDigitalIdentity><DigitalId><X509SKI>PxWGGXCj+NKIUPe/FVOiS18mojA=</X509SKI></DigitalId></ServiceDigitalIdentity><ServiceStatus>http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted</ServiceStatus><StatusStartingTime>2025-01-01T00:00:00Z</StatusStartingTime></ServiceHistoryInstance></ServiceHistory></TSPService>"#
    );
    parse_tsl_xml(&trusted_list_document(&provider(&services))).unwrap()
}

fn trusted_list_with_ca_and_qeaa_services() -> TrustedList {
    let certificate = certificate_base64();
    let services = format!(
        r#"<TSPService><ServiceInformation><ServiceTypeIdentifier>http://uri.etsi.org/TrstSvc/Svctype/CA/QC</ServiceTypeIdentifier><ServiceName><Name xml:lang="en">Qualified CA</Name></ServiceName><ServiceDigitalIdentity><DigitalId><X509Certificate>{certificate}</X509Certificate></DigitalId></ServiceDigitalIdentity><ServiceStatus>http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted</ServiceStatus><StatusStartingTime>2026-01-01T00:00:00Z</StatusStartingTime></ServiceInformation></TSPService><TSPService><ServiceInformation><ServiceTypeIdentifier>http://uri.etsi.org/TrstSvc/Svctype/EAA/Q</ServiceTypeIdentifier><ServiceName><Name xml:lang="en">Qualified EAA</Name></ServiceName><ServiceDigitalIdentity><DigitalId><X509Certificate>{certificate}</X509Certificate></DigitalId></ServiceDigitalIdentity><ServiceStatus>http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted</ServiceStatus><StatusStartingTime>2026-01-01T00:00:00Z</StatusStartingTime></ServiceInformation></TSPService>"#
    );
    parse_tsl_xml(&trusted_list_document(&provider(&services))).unwrap()
}

#[test]
fn authorizes_qeaa_issuer() {
    let cert = dummy_cert();
    let tsl = trusted_list("http://uri.etsi.org/TrstSvc/Svctype/EAA/Q");

    let decision = trusted_decision(cert);

    authorize_issuer(&decision, &tsl, AuthorizationPurpose::QeaaIssuer).unwrap();
}

#[test]
fn evaluates_every_matching_service_before_rejecting_the_purpose() {
    let tsl = trusted_list_with_ca_and_qeaa_services();
    let decision = trusted_decision(dummy_cert());

    authorize_issuer(&decision, &tsl, AuthorizationPurpose::QeaaIssuer).unwrap();
}

#[test]
fn rejects_wrong_service_type() {
    let cert = dummy_cert();
    let tsl = trusted_list("http://uri.etsi.org/TrstSvc/Svctype/CA/QC");

    let decision = trusted_decision(cert);

    let err = authorize_issuer(&decision, &tsl, AuthorizationPurpose::QeaaIssuer).unwrap_err();

    assert!(matches!(
        err,
        identity_credential_trust_api::TrustApiError::ServiceTypeMismatch
    ));
}

#[test]
fn authorizes_ca_qc_leaf_through_matching_qualification_criteria() {
    let cert = dummy_cert();
    let extension = qualification_extension_with_qualifiers(
        r#"<sie:Qualifier uri="http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCStatement"/><sie:Qualifier uri="http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCForWSA"/>"#,
    );
    let tsl = trusted_list_with_extensions("http://uri.etsi.org/TrstSvc/Svctype/CA/QC", &extension);
    let decision = trusted_decision(cert);

    authorize_issuer(&decision, &tsl, AuthorizationPurpose::QwacTlsServer).unwrap();
}

#[test]
fn purpose_qualifier_alone_does_not_make_a_certificate_qualified() {
    let cert = dummy_cert();
    let extension =
        qualification_extension("http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCForWSA");
    let tsl = trusted_list_with_extensions("http://uri.etsi.org/TrstSvc/Svctype/CA/QC", &extension);
    let decision = trusted_decision(cert);

    let error = authorize_issuer(&decision, &tsl, AuthorizationPurpose::QwacTlsServer).unwrap_err();

    assert!(matches!(
        error,
        identity_credential_trust_api::TrustApiError::ServiceTypeMismatch
    ));
}

#[test]
fn qualified_website_policy_establishes_qualification_and_purpose() {
    let mut certificate = dummy_cert();
    certificate.profile.certificate_policies = vec![CertificatePolicyId::QevcpWeb];
    let tsl = trusted_list("http://uri.etsi.org/TrstSvc/Svctype/CA/QC");
    let decision = trusted_decision(certificate);

    authorize_issuer(&decision, &tsl, AuthorizationPurpose::QwacTlsServer).unwrap();
}

#[test]
fn matching_not_qualified_extension_overrides_certificate_claims() {
    let cert = dummy_cert();
    let extension =
        qualification_extension("http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/NotQualified");
    let tsl = trusted_list_with_extensions("http://uri.etsi.org/TrstSvc/Svctype/CA/QC", &extension);
    let decision = trusted_decision(cert);

    let error = authorize_issuer(&decision, &tsl, AuthorizationPurpose::QwacTlsServer).unwrap_err();

    assert!(matches!(
        error,
        identity_credential_trust_api::TrustApiError::ServiceTypeMismatch
    ));
}

#[test]
fn arbitrary_suffix_does_not_become_a_standard_service_type() {
    let cert = dummy_cert();
    let tsl = trusted_list("https://example.test/QCForElectronicAttestations");
    let decision = trusted_decision(cert);

    let error = authorize_issuer(&decision, &tsl, AuthorizationPurpose::QeaaIssuer).unwrap_err();

    assert!(matches!(
        error,
        identity_credential_trust_api::TrustApiError::ServiceTypeUnknown
    ));
}

#[test]
fn authorizes_using_the_state_effective_at_the_trusted_evaluation_time() {
    let decision = trusted_decision_at(dummy_cert(), 1_751_328_000);
    let tsl = trusted_list_with_history();

    authorize_issuer(&decision, &tsl, AuthorizationPurpose::QeaaIssuer).unwrap();
}

#[test]
fn rejects_after_a_historically_granted_service_is_withdrawn() {
    let decision = trusted_decision_at(dummy_cert(), 1_780_000_000);
    let tsl = trusted_list_with_history();

    let error = authorize_issuer(&decision, &tsl, AuthorizationPurpose::QeaaIssuer).unwrap_err();

    assert!(matches!(
        error,
        identity_credential_trust_api::TrustApiError::ServiceNotActive
    ));
}
