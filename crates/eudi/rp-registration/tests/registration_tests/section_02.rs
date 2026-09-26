// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

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
fn wrprc_credentials_authorize_only_registered_metadata_and_claims(
) -> Result<(), RegistrationError> {
    let parsed = parse_registration_certificate(include_bytes!(
        "../vectors/valid-wrprc-payload.json"
    ))?;
    let relying_party = WalletRelyingParty::from_json(WRP.as_bytes())?;
    let request = &relying_party.services()[0].intended_uses()[0].credentials()[0];

    assert_eq!(parsed.registered_credentials().len(), 1);
    assert!(parsed.authorizes_credential_request(request));

    let unauthorized = WRP.replace("urn:example:pid", "urn:example:other");
    let relying_party = WalletRelyingParty::from_json(unauthorized.as_bytes())?;
    let request = &relying_party.services()[0].intended_uses()[0].credentials()[0];
    assert!(!parsed.authorizes_credential_request(request));
    Ok(())
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
