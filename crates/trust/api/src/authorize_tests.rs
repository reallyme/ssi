// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Unit tests for TSL-based trust authorization over authenticated list data.

use super::authorize_issuer_in_list;
use crate::{AuthorizationPurpose, TrustApiError, TrustedListPolicyErrorReason};

use envelopes_x509::model::X509Certificate;
use envelopes_x509::CertificatePolicyId;
use identity_trust_tsl_core::{parse_tsl_xml, TrustedList, TslError};
use reallyme_trust_core::{
    TrustDecision, TrustEvidence, TrustOutcome, TrustPolicyId, TrustPurpose,
};

/// 2026-01-09T23:06:40Z: inside the fixture list's issue/next-update window.
const WITHIN_LIST_VALIDITY: i64 = 1_768_000_000;
/// 2026-01-21T08:53:20Z: after the pre-published 2026-01-15 transition.
const AFTER_PRE_PUBLISHED_TRANSITION: i64 = 1_769_000_000;
/// 2026-02-01T00:00:00Z: the fixture list's NextUpdate.
const AT_NEXT_UPDATE: i64 = 1_769_904_000;
/// 2025-12-31T23:59:59Z: one second before ListIssueDateTime (beyond skew
/// once the admitted clock skew is subtracted).
const BEFORE_ISSUE: i64 = 1_767_225_600 - 301;

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
    trusted_decision_at(cert, WITHIN_LIST_VALIDITY)
}

fn trusted_chain_decision_at(
    certs: Vec<X509Certificate>,
    evaluated_at_unix_seconds: i64,
) -> TrustDecision {
    let mut decision = trusted_decision_at(dummy_cert(), evaluated_at_unix_seconds);
    decision.chain = Some(envelopes_x509::X509Chain { certs });
    decision
}

/// A distinct end-entity certificate issued (for authorization purposes) by
/// the CA/QC service key in `dummy_cert`. Its own qualified claims are
/// cleared so each test states the qualification it relies on.
fn issued_leaf() -> X509Certificate {
    let encoded: String = include_str!("../../x509/tests/fixtures/qwac_server_auth_cert.der.b64")
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect();
    let der = reallyme_codec::base64::base64_to_bytes(&encoded).unwrap();
    let mut leaf = envelopes_x509::parse_cert_der(&der).unwrap();
    leaf.profile.certificate_policies.clear();
    leaf.profile.qc_statement_ids.clear();
    leaf.profile.qc_types.clear();
    leaf
}

/// Chain whose leaf is issued by the CA/QC service certificate.
fn ca_issued_decision(leaf: X509Certificate) -> TrustDecision {
    trusted_chain_decision_at(vec![leaf, dummy_cert()], WITHIN_LIST_VALIDITY)
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
        r#"<TSPService><ServiceInformation><ServiceTypeIdentifier>http://uri.etsi.org/TrstSvc/Svctype/EAA/Q</ServiceTypeIdentifier><ServiceName><Name xml:lang="en">Service</Name></ServiceName><ServiceDigitalIdentity><DigitalId><X509Certificate>{certificate}</X509Certificate></DigitalId></ServiceDigitalIdentity><ServiceStatus>http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/withdrawn</ServiceStatus><StatusStartingTime>2026-01-15T00:00:00Z</StatusStartingTime></ServiceInformation><ServiceHistory><ServiceHistoryInstance><ServiceTypeIdentifier>http://uri.etsi.org/TrstSvc/Svctype/EAA/Q</ServiceTypeIdentifier><ServiceName><Name xml:lang="en">Historical service</Name></ServiceName><ServiceDigitalIdentity><DigitalId><X509SKI>PxWGGXCj+NKIUPe/FVOiS18mojA=</X509SKI></DigitalId></ServiceDigitalIdentity><ServiceStatus>http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted</ServiceStatus><StatusStartingTime>2025-01-01T00:00:00Z</StatusStartingTime></ServiceHistoryInstance></ServiceHistory></TSPService>"#
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

    authorize_issuer_in_list(&decision, &tsl, AuthorizationPurpose::QeaaIssuer).unwrap();
}

#[test]
fn evaluates_every_matching_service_before_rejecting_the_purpose() {
    let tsl = trusted_list_with_ca_and_qeaa_services();
    let decision = trusted_decision(dummy_cert());

    authorize_issuer_in_list(&decision, &tsl, AuthorizationPurpose::QeaaIssuer).unwrap();
}

#[test]
fn rejects_wrong_service_type() {
    let cert = issued_leaf();
    let tsl = trusted_list("http://uri.etsi.org/TrstSvc/Svctype/CA/QC");

    let decision = ca_issued_decision(cert);

    let err =
        authorize_issuer_in_list(&decision, &tsl, AuthorizationPurpose::QeaaIssuer).unwrap_err();

    assert!(matches!(err, TrustApiError::ServiceTypeMismatch));
}

#[test]
fn authorizes_ca_qc_leaf_through_matching_qualification_criteria() {
    let cert = issued_leaf();
    let extension = qualification_extension_with_qualifiers(
        r#"<sie:Qualifier uri="http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCStatement"/><sie:Qualifier uri="http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCForWSA"/>"#,
    );
    let tsl = trusted_list_with_extensions("http://uri.etsi.org/TrstSvc/Svctype/CA/QC", &extension);
    let decision = ca_issued_decision(cert);

    authorize_issuer_in_list(&decision, &tsl, AuthorizationPurpose::QwacTlsServer).unwrap();
}

#[test]
fn purpose_qualifier_alone_does_not_make_a_certificate_qualified() {
    let cert = issued_leaf();
    let extension =
        qualification_extension("http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCForWSA");
    let tsl = trusted_list_with_extensions("http://uri.etsi.org/TrstSvc/Svctype/CA/QC", &extension);
    let decision = ca_issued_decision(cert);

    let error =
        authorize_issuer_in_list(&decision, &tsl, AuthorizationPurpose::QwacTlsServer).unwrap_err();

    assert!(matches!(error, TrustApiError::ServiceTypeMismatch));
}

#[test]
fn qualified_website_policy_establishes_qualification_and_purpose() {
    let mut certificate = issued_leaf();
    certificate.profile.certificate_policies = vec![CertificatePolicyId::QevcpWeb];
    let tsl = trusted_list("http://uri.etsi.org/TrstSvc/Svctype/CA/QC");
    let decision = ca_issued_decision(certificate);

    authorize_issuer_in_list(&decision, &tsl, AuthorizationPurpose::QwacTlsServer).unwrap();
}

#[test]
fn matching_not_qualified_extension_overrides_certificate_claims() {
    let cert = issued_leaf();
    let extension =
        qualification_extension("http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/NotQualified");
    let tsl = trusted_list_with_extensions("http://uri.etsi.org/TrstSvc/Svctype/CA/QC", &extension);
    let decision = ca_issued_decision(cert);

    let error =
        authorize_issuer_in_list(&decision, &tsl, AuthorizationPurpose::QwacTlsServer).unwrap_err();

    assert!(matches!(error, TrustApiError::ServiceTypeMismatch));
}

#[test]
fn arbitrary_suffix_does_not_become_a_standard_service_type() {
    let cert = dummy_cert();
    let tsl = trusted_list("https://example.test/QCForElectronicAttestations");
    let decision = trusted_decision(cert);

    let error =
        authorize_issuer_in_list(&decision, &tsl, AuthorizationPurpose::QeaaIssuer).unwrap_err();

    assert!(matches!(error, TrustApiError::ServiceTypeUnknown));
}

#[test]
fn authorizes_using_the_state_effective_at_the_trusted_evaluation_time() {
    let decision = trusted_decision_at(dummy_cert(), WITHIN_LIST_VALIDITY);
    let tsl = trusted_list_with_history();

    authorize_issuer_in_list(&decision, &tsl, AuthorizationPurpose::QeaaIssuer).unwrap();
}

#[test]
fn rejects_after_a_historically_granted_service_is_withdrawn() {
    let decision = trusted_decision_at(dummy_cert(), AFTER_PRE_PUBLISHED_TRANSITION);
    let tsl = trusted_list_with_history();

    let error =
        authorize_issuer_in_list(&decision, &tsl, AuthorizationPurpose::QeaaIssuer).unwrap_err();

    assert!(matches!(error, TrustApiError::ServiceNotActive));
}

fn history_row(status: &str, start: &str, identity: &str) -> String {
    format!(
        r#"<ServiceHistoryInstance><ServiceTypeIdentifier>http://uri.etsi.org/TrstSvc/Svctype/EAA/Q</ServiceTypeIdentifier><ServiceName><Name xml:lang="en">Historical service</Name></ServiceName><ServiceDigitalIdentity>{identity}</ServiceDigitalIdentity><ServiceStatus>http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/{status}</ServiceStatus><StatusStartingTime>{start}</StatusStartingTime></ServiceHistoryInstance>"#
    )
}

const FIXTURE_SKI_IDENTITY: &str =
    "<DigitalId><X509SKI>PxWGGXCj+NKIUPe/FVOiS18mojA=</X509SKI></DigitalId>";

fn trusted_list_with_history_rows(rows: &str) -> TrustedList {
    let certificate = certificate_base64();
    let services = format!(
        r#"<TSPService><ServiceInformation><ServiceTypeIdentifier>http://uri.etsi.org/TrstSvc/Svctype/EAA/Q</ServiceTypeIdentifier><ServiceName><Name xml:lang="en">Service</Name></ServiceName><ServiceDigitalIdentity><DigitalId><X509Certificate>{certificate}</X509Certificate></DigitalId></ServiceDigitalIdentity><ServiceStatus>http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted</ServiceStatus><StatusStartingTime>2026-01-15T00:00:00Z</StatusStartingTime></ServiceInformation><ServiceHistory>{rows}</ServiceHistory></TSPService>"#
    );
    parse_tsl_xml(&trusted_list_document(&provider(&services))).unwrap()
}

#[test]
fn rejects_a_list_that_is_not_fresh_at_the_evaluation_time() {
    let tsl = trusted_list("http://uri.etsi.org/TrstSvc/Svctype/EAA/Q");

    let expired = trusted_decision_at(dummy_cert(), AT_NEXT_UPDATE);
    assert!(matches!(
        authorize_issuer_in_list(&expired, &tsl, AuthorizationPurpose::QeaaIssuer).unwrap_err(),
        TrustApiError::TrustedListPolicy(TrustedListPolicyErrorReason::Expired)
    ));

    let before_issue = trusted_decision_at(dummy_cert(), BEFORE_ISSUE);
    assert!(matches!(
        authorize_issuer_in_list(&before_issue, &tsl, AuthorizationPurpose::QeaaIssuer)
            .unwrap_err(),
        TrustApiError::TrustedList(TslError::NotYetIssued)
    ));
}

#[test]
fn pre_published_current_state_does_not_govern_before_it_starts() {
    // Current state is granted from 2026-01-15; before that, the history row
    // (withdrawn from 2025-01-01) is the effective state.
    let tsl = trusted_list_with_history_rows(&history_row(
        "withdrawn",
        "2025-01-01T00:00:00Z",
        FIXTURE_SKI_IDENTITY,
    ));
    let before = trusted_decision_at(dummy_cert(), WITHIN_LIST_VALIDITY);
    assert!(matches!(
        authorize_issuer_in_list(&before, &tsl, AuthorizationPurpose::QeaaIssuer).unwrap_err(),
        TrustApiError::ServiceNotActive
    ));
    let after = trusted_decision_at(dummy_cert(), AFTER_PRE_PUBLISHED_TRANSITION);
    authorize_issuer_in_list(&after, &tsl, AuthorizationPurpose::QeaaIssuer).unwrap();
}

#[test]
fn unidentifiable_restrictive_history_row_blocks_an_older_grant() {
    // Granted from 2024, then a withdrawn row from 2025 whose key cannot be
    // identified. The withdrawn row must still end the older grant.
    let rows = format!(
        "{}{}",
        history_row("granted", "2024-01-01T00:00:00Z", FIXTURE_SKI_IDENTITY),
        history_row(
            "withdrawn",
            "2025-01-01T00:00:00Z",
            "<DigitalId><X509SubjectName>O=Unidentified</X509SubjectName></DigitalId>",
        ),
    );
    let tsl = trusted_list_with_history_rows(&rows);
    let decision = trusted_decision_at(dummy_cert(), WITHIN_LIST_VALIDITY);
    assert!(matches!(
        authorize_issuer_in_list(&decision, &tsl, AuthorizationPurpose::QeaaIssuer).unwrap_err(),
        TrustApiError::NotAuthorized
    ));
}

#[test]
fn different_type_history_row_blocks_an_older_same_type_grant() {
    let rows = format!(
        "{}{}",
        history_row("granted", "2024-01-01T00:00:00Z", FIXTURE_SKI_IDENTITY),
        history_row("granted", "2025-01-01T00:00:00Z", FIXTURE_SKI_IDENTITY).replace(
            "http://uri.etsi.org/TrstSvc/Svctype/EAA/Q",
            "http://uri.etsi.org/TrstSvc/Svctype/TSA/QTST",
        ),
    );
    let tsl = trusted_list_with_history_rows(&rows);
    let decision = trusted_decision_at(dummy_cert(), WITHIN_LIST_VALIDITY);
    assert!(matches!(
        authorize_issuer_in_list(&decision, &tsl, AuthorizationPurpose::QeaaIssuer).unwrap_err(),
        TrustApiError::ServiceTypeMismatch | TrustApiError::ServiceTypeUnknown
    ));
}

#[test]
fn ca_qc_service_key_on_the_leaf_alone_does_not_authorize() {
    let extension = qualification_extension_with_qualifiers(
        r#"<sie:Qualifier uri="http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCStatement"/><sie:Qualifier uri="http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCForWSA"/>"#,
    );
    let tsl = trusted_list_with_extensions("http://uri.etsi.org/TrstSvc/Svctype/CA/QC", &extension);
    // The leaf itself carries the CA/QC service key; nothing above it does.
    let decision = trusted_chain_decision_at(vec![dummy_cert()], WITHIN_LIST_VALIDITY);
    assert!(matches!(
        authorize_issuer_in_list(&decision, &tsl, AuthorizationPurpose::QwacTlsServer).unwrap_err(),
        TrustApiError::NotAuthorized
    ));
}

#[test]
fn historical_match_ignores_a_self_asserted_subject_key_identifier() {
    let tsl = trusted_list_with_history_rows(&history_row(
        "granted",
        "2025-01-01T00:00:00Z",
        FIXTURE_SKI_IDENTITY,
    ));
    // A different key whose SubjectKeyIdentifier extension claims the
    // historical service identifier must not match the historical state.
    let mut forged = issued_leaf();
    forged.subject_key_identifier = dummy_cert().subject_key_identifier.clone();
    let decision = trusted_decision_at(forged, WITHIN_LIST_VALIDITY);
    assert!(matches!(
        authorize_issuer_in_list(&decision, &tsl, AuthorizationPurpose::QeaaIssuer).unwrap_err(),
        TrustApiError::NotAuthorized
    ));

    // The genuine key matches because its identifier is computed from SPKI.
    let genuine = trusted_decision_at(dummy_cert(), WITHIN_LIST_VALIDITY);
    authorize_issuer_in_list(&genuine, &tsl, AuthorizationPurpose::QeaaIssuer).unwrap();
}
