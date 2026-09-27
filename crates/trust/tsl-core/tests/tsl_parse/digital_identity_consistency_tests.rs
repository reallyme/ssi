// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

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
fn rejects_current_service_certificates_with_the_same_key_but_different_subject_names() {
    let xml = document_with_certificate_pair(
        shared_key_leaf_certificate_base64(),
        shared_key_different_subject_certificate_base64(),
    );

    assert_eq!(
        parse_tsl_xml(&xml).unwrap_err(),
        TslError::DigitalIdentity(
            identity_trust_tsl_core::TslDigitalIdentityFailure::SubjectNameMismatch
        )
    );
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
