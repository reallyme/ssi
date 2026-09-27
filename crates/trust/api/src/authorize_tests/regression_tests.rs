// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#[test]
fn malformed_qualification_cannot_hide_a_matched_key_from_qwac_scope() {
    let malformed = qualification_and_additional_info_extensions(
        r#"<sie:Qualifier uri="http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCForWSA"/>"#,
        "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/ForWebSiteAuthentication",
    )
    .replace(
        "<sie:KeyUsage><sie:KeyUsageBit name=\"digitalSignature\">true</sie:KeyUsageBit></sie:KeyUsage>",
        r#"<sie:PolicySet xmlns:xades="http://uri.etsi.org/01903/v1.3.2#"><sie:PolicyIdentifier><xades:Identifier>https://example.test/not-an-oid</xades:Identifier></sie:PolicyIdentifier></sie:PolicySet>"#,
    );
    let granted = qualification_and_additional_info_extensions(
        r#"<sie:Qualifier uri="http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCStatement"/><sie:Qualifier uri="http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCForWSA"/>"#,
        "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/ForWebSiteAuthentication",
    );
    let services = format!(
        "{}{}",
        ca_qc_service("Malformed", "withdrawn", &malformed, "2026-01-02T00:00:00Z"),
        ca_qc_service("Granted", "granted", &granted, "2026-01-01T00:00:00Z")
    );
    let tsl = trusted_list_with_services(&services);
    let indeterminate = tsl
        .services()
        .find(|service| {
            service.status == identity_trust_tsl_core::TrustServiceStatus::Indeterminate
        })
        .expect("malformed qualification must isolate the affected service");
    assert!(indeterminate
        .additional_service_information
        .iter()
        .any(|information| matches!(
            information.kind,
            identity_trust_tsl_core::AdditionalServiceInformationKind::ForWebsiteAuthentication
        )));
    let error = authorize_test_chain_in_list(
        &ca_issued_decision(issued_leaf()),
        &tsl,
        AuthorizationPurpose::QwacTlsServer,
    )
    .unwrap_err();

    assert!(matches!(error, TrustApiError::ServiceStatusUnknown));
}

#[test]
fn history_anomaly_remains_an_indeterminate_barrier_for_past_decisions() {
    let certificate = certificate_base64();
    let extension = qualification_and_additional_info_extensions(
        r#"<sie:Qualifier uri="http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCStatement"/><sie:Qualifier uri="http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCForWSA"/>"#,
        "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/ForWebSiteAuthentication",
    );
    let anomalous = format!(
        r#"<TSPService><ServiceInformation><ServiceTypeIdentifier>http://uri.etsi.org/TrstSvc/Svctype/CA/QC</ServiceTypeIdentifier><ServiceName><Name xml:lang="en">Anomalous</Name></ServiceName><ServiceDigitalIdentity><DigitalId><X509Certificate>{certificate}</X509Certificate></DigitalId></ServiceDigitalIdentity><ServiceStatus>http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted</ServiceStatus><StatusStartingTime>2026-01-15T00:00:00Z</StatusStartingTime>{extension}</ServiceInformation><ServiceHistory><ServiceHistoryInstance><ServiceTypeIdentifier>http://uri.etsi.org/TrstSvc/Svctype/CA/QC</ServiceTypeIdentifier><ServiceName><Name xml:lang="en">Renamed future row</Name></ServiceName><ServiceDigitalIdentity><DigitalId><X509SKI>PxWGGXCj+NKIUPe/FVOiS18mojA=</X509SKI></DigitalId></ServiceDigitalIdentity><ServiceStatus>http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted</ServiceStatus><StatusStartingTime>2026-02-01T00:00:00Z</StatusStartingTime></ServiceHistoryInstance><ServiceHistoryInstance><ServiceTypeIdentifier>http://uri.etsi.org/TrstSvc/Svctype/CA/QC</ServiceTypeIdentifier><ServiceName><Name xml:lang="en">Withdrawn interval</Name></ServiceName><ServiceDigitalIdentity><DigitalId><X509SKI>PxWGGXCj+NKIUPe/FVOiS18mojA=</X509SKI></DigitalId></ServiceDigitalIdentity><ServiceStatus>http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/withdrawn</ServiceStatus><StatusStartingTime>2026-01-05T00:00:00Z</StatusStartingTime></ServiceHistoryInstance></ServiceHistory></TSPService>"#,
    );
    let sibling = ca_qc_service(
        "Granted sibling",
        "granted",
        &extension,
        "2026-01-01T00:00:00Z",
    );
    for services in [
        format!("{anomalous}{sibling}"),
        format!("{sibling}{anomalous}"),
    ] {
        let tsl = trusted_list_with_services(&services);
        let service = tsl.services().next().unwrap();
        assert_eq!(service.history.len(), 1);
        assert_eq!(
            service.status,
            identity_trust_tsl_core::TrustServiceStatus::Indeterminate
        );

        assert!(matches!(
            authorize_test_chain_in_list(
                &ca_issued_decision(issued_leaf()),
                &tsl,
                AuthorizationPurpose::QwacTlsServer,
            ),
            Err(TrustApiError::ServiceStatusUnknown)
        ));
    }
}

#[test]
fn pre_2016_qualified_decisions_report_unknown_status() {
    let tsl = trusted_list("http://uri.etsi.org/TrstSvc/Svctype/CA/QC");
    let mut leaf = issued_leaf();
    leaf.not_before = time::OffsetDateTime::from_unix_timestamp(1_467_323_999).unwrap();
    let decision = ca_issued_decision(leaf);

    assert!(matches!(
        authorize_test_chain_in_list(&decision, &tsl, AuthorizationPurpose::QwacTlsServer),
        Err(TrustApiError::ServiceStatusUnknown)
    ));
}
