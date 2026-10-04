// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_eudi_rp_registration::{
    authenticate_access_certificate_association, parse_registration_certificate,
    AccessCertificateBinding, ArtifactDigest, RegistrationCertificatePolicy, RegistrationError,
    RegistrationErrorReason,
};

#[test]
fn wrpac_association_projects_standard_holder_and_exact_local_bindings(
) -> Result<(), RegistrationError> {
    let leaf_der = wrpac_leaf()?;
    let leaf_digest = ArtifactDigest::sha256(&leaf_der);
    let registry_reference_digest = ArtifactDigest::sha256(b"registry-reference");
    let binding = AccessCertificateBinding::try_new(
        leaf_digest,
        "VATMT-1",
        "service-1",
        Some("customer-association-1"),
        registry_reference_digest,
    )?;
    let evaluation_time = time::OffsetDateTime::UNIX_EPOCH + time::Duration::seconds(1_800_000_000);
    let authenticated =
        authenticate_access_certificate_association(&leaf_der, evaluation_time, binding)?;
    assert_eq!(authenticated.leaf_certificate_digest(), leaf_digest);
    assert_eq!(authenticated.holder_relying_party_id(), "VATMT-1");
    assert_eq!(authenticated.holder_service_id(), "service-1");
    assert_eq!(
        authenticated.intermediary_association_id(),
        Some("customer-association-1")
    );
    assert_eq!(
        authenticated.national_register_reference_digest(),
        registry_reference_digest
    );
    assert!(authenticated.valid_from_unix_seconds() < authenticated.valid_until_unix_seconds());
    Ok(())
}

#[test]
fn wrpac_association_rejects_substituted_holder() -> Result<(), RegistrationError> {
    let leaf_der = wrpac_leaf()?;
    let binding = AccessCertificateBinding::try_new(
        ArtifactDigest::sha256(&leaf_der),
        "VATMT-substituted",
        "service-1",
        None,
        ArtifactDigest::sha256(b"registry-reference"),
    )?;
    let evaluation_time = time::OffsetDateTime::UNIX_EPOCH + time::Duration::seconds(1_800_000_000);
    let error =
        authenticate_access_certificate_association(&leaf_der, evaluation_time, binding).err();
    assert_eq!(
        error.map(RegistrationError::reason),
        Some(RegistrationErrorReason::SemanticBindingMismatch)
    );
    Ok(())
}

#[test]
fn wrprc_status_and_validity_are_parsed_strictly() -> Result<(), RegistrationError> {
    let payload = include_bytes!("../vectors/valid-wrprc-payload.json");
    let parsed = parse_registration_certificate(payload)?;
    assert_eq!(parsed.relying_party_id(), "NTRCH-123");
    assert_eq!(parsed.status_list_index(), 9);
    assert_eq!(parsed.registry_uri(), "https://registry.example/entry/123");
    assert_eq!(parsed.status_list_uri(), "https://status.example/list");
    assert_eq!(parsed.issued_at(), 100);
    assert_eq!(parsed.expires_at(), 200);
    assert_eq!(
        parsed.certificate_policy(),
        RegistrationCertificatePolicy::EtsiTs119475Wrprc
    );
    Ok(())
}

#[test]
fn wrprc_requires_the_normative_policy_oid_and_https_cp_cps_location() {
    let wrong_policy = include_str!("../vectors/valid-wrprc-payload.json")
        .replace("0.4.0.19475.3.1", "0.4.0.19475.3.2");
    let policy_error = parse_registration_certificate(wrong_policy.as_bytes()).err();
    assert_eq!(
        policy_error.map(RegistrationError::reason),
        Some(RegistrationErrorReason::CertificateProfileMismatch)
    );

    let insecure_location = include_str!("../vectors/valid-wrprc-payload.json").replace(
        "https://registrar.example/certificate-policy",
        "http://registrar.example/certificate-policy",
    );
    let location_error = parse_registration_certificate(insecure_location.as_bytes()).err();
    assert_eq!(
        location_error.map(RegistrationError::reason),
        Some(RegistrationErrorReason::InvalidUri)
    );
}

#[test]
fn wrprc_rejects_oversized_signed_lookup_uris() {
    let payload = include_str!("../vectors/valid-wrprc-payload.json");
    for (original, oversized) in [
        ("https://registry.example/entry/123", format!("https://registry.example/{}", "a".repeat(2_048))),
        ("https://status.example/list", format!("https://status.example/{}", "a".repeat(2_048))),
    ] {
        let substituted = payload.replace(original, &oversized);
        assert_eq!(
            parse_registration_certificate(substituted.as_bytes())
                .err()
                .map(RegistrationError::reason),
            Some(RegistrationErrorReason::InvalidField)
        );
    }
}

#[test]
fn wrprc_rejects_non_normative_entitlement_identifiers() {
    let payload = include_str!("../vectors/valid-wrprc-payload.json").replace(
        "https://uri.etsi.org/19475/Entitlement/Service_Provider",
        "Service_Provider",
    );
    let error = parse_registration_certificate(payload.as_bytes()).err();
    assert_eq!(
        error.map(RegistrationError::reason),
        Some(RegistrationErrorReason::InvalidField)
    );
}

#[test]
fn wrprc_credentials_are_parsed_as_bounded_authorization_inputs(
) -> Result<(), RegistrationError> {
    let parsed = parse_registration_certificate(include_bytes!(
        "../vectors/valid-wrprc-payload.json"
    ))?;
    assert_eq!(parsed.registered_credentials().len(), 1);
    Ok(())
}

#[test]
fn wrprc_retains_signed_purpose_and_optional_intended_use() -> Result<(), RegistrationError> {
    let payload = include_str!("../vectors/valid-wrprc-payload.json");
    let without_id = parse_registration_certificate(payload.as_bytes())?;
    assert_eq!(without_id.intended_use_id(), None);
    assert_eq!(without_id.purpose()[0].language(), "en");
    assert_eq!(without_id.purpose()[0].content(), "Verify age");
    assert_eq!(without_id.service_description()[0].content(), "service");
    assert_eq!(without_id.privacy_policy_uris()[0].expose(), "https://rp.example/privacy");

    let with_id = payload.replace(
        "\"purpose\":",
        "\"intended_use_id\": \"age-check\", \"purpose\":",
    );
    let parsed = parse_registration_certificate(with_id.as_bytes())?;
    assert_eq!(parsed.intended_use_id(), Some("age-check"));
    Ok(())
}

#[test]
fn wrprc_rejects_malformed_signed_purpose_and_policy() {
    let payload = include_str!("../vectors/valid-wrprc-payload.json");
    let malformed_purpose = payload.replace(
        "\"purpose\": [{\"lang\": \"en\", \"content\": \"Verify age\"}]",
        "\"purpose\": [{\"lang\": \"en\", \"content\": \"Verify age\", \"extra\": true}]",
    );
    let malformed_policy = payload.replace(
        "\"privacy_policy\": [\"https://rp.example/privacy\"]",
        "\"privacy_policy\": [\"http://rp.example/privacy\"]",
    );
    assert!(parse_registration_certificate(malformed_purpose.as_bytes()).is_err());
    assert!(parse_registration_certificate(malformed_policy.as_bytes()).is_err());
}

#[test]
fn wrprc_duplicate_entitlements_are_rejected() {
    let payload = include_str!("../vectors/valid-wrprc-payload.json");
    let duplicated = payload.replace(
        r#""entitlements": ["https://uri.etsi.org/19475/Entitlement/Service_Provider"]"#,
        r#""entitlements": ["https://uri.etsi.org/19475/Entitlement/Service_Provider", "https://uri.etsi.org/19475/Entitlement/Service_Provider"]"#,
    );
    assert_eq!(
        parse_registration_certificate(duplicated.as_bytes())
            .err()
            .map(RegistrationError::reason),
        Some(RegistrationErrorReason::InvalidField)
    );
}

#[test]
fn digest_constructor_retains_fixed_width() {
    let digest = ArtifactDigest::from_bytes([7_u8; 32]);
    assert_eq!(digest.as_bytes(), &[7_u8; 32]);
}

fn wrpac_leaf() -> Result<Vec<u8>, RegistrationError> {
    reallyme_codec::base64::base64_to_bytes(
        include_str!("../vectors/wrpac-ncp-legal.der.b64").trim(),
    )
    .map_err(|_error| RegistrationError::Invalid(RegistrationErrorReason::InvalidCertificate))
}
