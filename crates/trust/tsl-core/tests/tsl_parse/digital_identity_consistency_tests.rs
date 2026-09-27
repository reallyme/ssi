// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#[test]
fn enforces_history_ski_without_a_certificate() {
    let current_certificate = certificate_base64();
    let current_ski = certificate_ski_base64();
    let historical_ski_identity =
        format!("<DigitalId><X509SKI>{current_ski}</X509SKI></DigitalId>");
    let current = format!(
        r#"<TSPService><ServiceInformation><ServiceTypeIdentifier>https://future.example/type</ServiceTypeIdentifier><ServiceName><Name xml:lang="en">Service</Name></ServiceName><ServiceDigitalIdentity><DigitalId><X509Certificate>{current_certificate}</X509Certificate></DigitalId></ServiceDigitalIdentity><ServiceStatus>http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted</ServiceStatus><StatusStartingTime>2025-01-01T00:00:00Z</StatusStartingTime></ServiceInformation><ServiceHistory><ServiceHistoryInstance><ServiceTypeIdentifier>https://future.example/type</ServiceTypeIdentifier><ServiceName><Name xml:lang="en">Historical service</Name></ServiceName><ServiceDigitalIdentity>{historical_ski_identity}</ServiceDigitalIdentity><ServiceStatus>http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/withdrawn</ServiceStatus><StatusStartingTime>2024-01-01T00:00:00Z</StatusStartingTime></ServiceHistoryInstance></ServiceHistory></TSPService>"#
    );
    let valid = document(&provider(&current));
    assert!(parse_tsl_xml(&valid).is_ok());

    let missing_ski = valid.replace(
        &historical_ski_identity,
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
        &historical_ski_identity,
        &format!(
            "{historical_ski_identity}<DigitalId><X509Certificate>{current_certificate}</X509Certificate></DigitalId>"
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
        Some(certificate_method_one_ski().as_slice())
    );
}

fn shared_key_leaf_certificate_base64() -> &'static str {
    include_str!("../fixtures/shared_key_base.der.b64")
}

fn shared_key_different_subject_certificate_base64() -> &'static str {
    include_str!("../fixtures/shared_key_subject.der.b64")
}

fn shared_key_ca_certificate_base64() -> &'static str {
    include_str!("../fixtures/shared_key_ca.der.b64")
}

fn document_with_certificate_pair(first: &str, second: &str) -> String {
    document_with_service_extension("")
        .replace(&certificate_base64(), first)
        .replace(
            "</ServiceDigitalIdentity>",
            &format!(
                "<DigitalId><X509Certificate>{second}</X509Certificate></DigitalId></ServiceDigitalIdentity>"
            ),
        )
}

#[test]
fn accepts_current_service_certificates_with_the_same_key_and_different_subject_names() {
    let xml = document_with_certificate_pair(
        shared_key_leaf_certificate_base64(),
        shared_key_different_subject_certificate_base64(),
    );

    let parsed = parse_tsl_xml(&xml).unwrap();
    assert_eq!(parsed.services().next().unwrap().certificates_der().len(), 2);
}

#[test]
fn rejects_current_service_certificates_with_the_same_key_but_different_ca_flags() {
    let xml = document_with_certificate_pair(
        shared_key_leaf_certificate_base64(),
        shared_key_ca_certificate_base64(),
    );

    assert_eq!(
        parse_tsl_xml(&xml).unwrap_err(),
        TslError::DigitalIdentity(
            identity_trust_tsl_core::TslDigitalIdentityFailure::CertificateAuthorityMismatch
        )
    );
}
