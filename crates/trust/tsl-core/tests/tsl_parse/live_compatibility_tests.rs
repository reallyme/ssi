// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#[test]
fn noncanonical_ski_lengths_parse_but_do_not_bind_history() {
    let certificate = certificate_base64();
    let service = format!(
        r#"<TSPService><ServiceInformation><ServiceTypeIdentifier>https://future.example/type</ServiceTypeIdentifier><ServiceName><Name xml:lang="en">Service</Name></ServiceName><ServiceDigitalIdentity><DigitalId><X509Certificate>{certificate}</X509Certificate></DigitalId></ServiceDigitalIdentity><ServiceStatus>http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted</ServiceStatus><StatusStartingTime>2025-01-01T00:00:00Z</StatusStartingTime></ServiceInformation><ServiceHistory><ServiceHistoryInstance><ServiceTypeIdentifier>https://future.example/type</ServiceTypeIdentifier><ServiceName><Name xml:lang="en">Historical</Name></ServiceName><ServiceDigitalIdentity><DigitalId><X509SKI>{{ski}}</X509SKI></DigitalId></ServiceDigitalIdentity><ServiceStatus>http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/withdrawn</ServiceStatus><StatusStartingTime>2024-01-01T00:00:00Z</StatusStartingTime></ServiceHistoryInstance></ServiceHistory></TSPService>"#
    );
    for ski in [
        "AQEBAQEBAQE=",
        "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=",
    ] {
        let parsed = parse_tsl_xml(&document(&provider(&service.replace("{ski}", ski)))).unwrap();
        let history = &parsed.providers[0].services[0].history;
        assert_eq!(history.len(), 1);
        assert!(history[0].digital_identity.is_none());
    }

    let oversized = codec_base64::bytes_to_base64(&[1; 513]);
    assert_eq!(
        parse_tsl_xml(&document(&provider(&service.replace("{ski}", &oversized)))).unwrap_err(),
        TslError::DigitalIdentity(
            identity_trust_tsl_core::TslDigitalIdentityFailure::MalformedRepresentation
        )
    );
}

#[test]
fn identical_current_state_repeated_in_history_is_dropped() {
    let certificate = certificate_base64();
    let certificate_ski = certificate_ski_base64();
    let service = format!(
        r#"<TSPService><ServiceInformation><ServiceTypeIdentifier>https://future.example/type</ServiceTypeIdentifier><ServiceName><Name xml:lang="en">Service</Name></ServiceName><ServiceDigitalIdentity><DigitalId><X509Certificate>{certificate}</X509Certificate></DigitalId></ServiceDigitalIdentity><ServiceStatus>http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted</ServiceStatus><StatusStartingTime>2025-01-01T00:00:00Z</StatusStartingTime></ServiceInformation><ServiceHistory><ServiceHistoryInstance><ServiceTypeIdentifier>https://future.example/type</ServiceTypeIdentifier><ServiceName><Name xml:lang="en">Service</Name></ServiceName><ServiceDigitalIdentity><DigitalId><X509SKI>{certificate_ski}</X509SKI></DigitalId></ServiceDigitalIdentity><ServiceStatus>http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted</ServiceStatus><StatusStartingTime>2025-01-01T00:00:00Z</StatusStartingTime></ServiceHistoryInstance></ServiceHistory></TSPService>"#
    );
    let parsed = parse_tsl_xml(&document(&provider(&service))).unwrap();
    let projected = &parsed.providers[0].services[0];
    assert_eq!(projected.status, TrustServiceStatus::Granted);
    assert!(projected.history.is_empty());
}
