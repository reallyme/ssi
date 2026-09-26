// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{
    common_pid, validate_attestation, AttestationCategory, AttestationFormat,
    CommonAttestationFacts, ConformanceError, FormatFacts, JsonLdFacts, StatusFacts,
    X509AttributeCertificateFacts,
};

fn format_common(
    format: AttestationFormat,
    type_identifier: &'static str,
) -> CommonAttestationFacts<'static> {
    CommonAttestationFacts {
        category: AttestationCategory::Eaa,
        holder_public_key_bound: false,
        status: StatusFacts::Absent,
        format,
        type_identifier,
        ..common_pid(format, type_identifier)
    }
}

#[test]
fn accepts_complete_json_ld_eaa_profile() {
    let common = format_common(AttestationFormat::JsonLdJose, "urn:example:eaa:json-ld");
    let format = FormatFacts::JsonLd(JsonLdFacts {
        vc_data_model_2: true,
        context_and_type_valid: true,
        credential_subject_valid: true,
        enveloping_proof_valid: true,
    });

    assert_eq!(validate_attestation(&common, &format), Ok(()));
}

#[test]
fn rejects_json_ld_eaa_without_valid_enveloping_proof() {
    let common = format_common(AttestationFormat::JsonLdJose, "urn:example:eaa:json-ld");
    let format = FormatFacts::JsonLd(JsonLdFacts {
        vc_data_model_2: true,
        context_and_type_valid: true,
        credential_subject_valid: true,
        enveloping_proof_valid: false,
    });

    assert_eq!(
        validate_attestation(&common, &format),
        Err(ConformanceError::InvalidJsonLdProfile)
    );
}

#[test]
fn accepts_complete_x509_attribute_certificate_eaa_profile() {
    let common = format_common(
        AttestationFormat::X509AttributeCertificate,
        "urn:example:eaa:x509-attribute-certificate",
    );
    let format = FormatFacts::X509AttributeCertificate(X509AttributeCertificateFacts {
        syntax_valid: true,
        mandatory_fields_valid: true,
        extensions_valid: true,
    });

    assert_eq!(validate_attestation(&common, &format), Ok(()));
}

#[test]
fn rejects_x509_attribute_certificate_eaa_with_invalid_extensions() {
    let common = format_common(
        AttestationFormat::X509AttributeCertificate,
        "urn:example:eaa:x509-attribute-certificate",
    );
    let format = FormatFacts::X509AttributeCertificate(X509AttributeCertificateFacts {
        syntax_valid: true,
        mandatory_fields_valid: true,
        extensions_valid: false,
    });

    assert_eq!(
        validate_attestation(&common, &format),
        Err(ConformanceError::InvalidX509AttributeCertificateProfile)
    );
}

#[test]
fn rejects_natural_person_pid_in_json_ld_and_x509_attribute_certificate_formats() {
    let json_ld = common_pid(AttestationFormat::JsonLdJose, "urn:example:pid:json-ld");
    let json_ld_format = FormatFacts::JsonLd(JsonLdFacts {
        vc_data_model_2: true,
        context_and_type_valid: true,
        credential_subject_valid: true,
        enveloping_proof_valid: true,
    });
    assert_eq!(
        validate_attestation(&json_ld, &json_ld_format),
        Err(ConformanceError::InvalidAttestationType)
    );

    let x509 = common_pid(
        AttestationFormat::X509AttributeCertificate,
        "urn:example:pid:x509-attribute-certificate",
    );
    let x509_format = FormatFacts::X509AttributeCertificate(X509AttributeCertificateFacts {
        syntax_valid: true,
        mandatory_fields_valid: true,
        extensions_valid: true,
    });
    assert_eq!(
        validate_attestation(&x509, &x509_format),
        Err(ConformanceError::InvalidAttestationType)
    );
}
