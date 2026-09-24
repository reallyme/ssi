// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#[test]
fn eu_tax_profile_protects_tax_identifier() {
    let registry = eu_tax_v1();

    validate_registry(&registry).unwrap();
    assert!(registry.claims.contains_key("tax_identifier"));
    assert!(registry.claims.contains_key("tax_reference_number"));
    assert!(registry.claims.contains_key("vat_registration_number"));
    assert!(
        validate_disclosure(&registry, "/claims/tax_identifier", DisclosureMode::Reveal).is_err()
    );
    assert!(validate_disclosure(&registry, "/claims/tax_identifier", DisclosureMode::Eq).is_ok());

    let mut payload = BTreeMap::new();
    payload.insert(
        "tax_identifier".to_owned(),
        ClaimValue::String("TAX-123456".to_owned()),
    );
    payload.insert(
        "tax_residence_country".to_owned(),
        ClaimValue::String("MT".to_owned()),
    );
    payload.insert("tax_year".to_owned(), ClaimValue::Unsigned(2026));
    payload.insert(
        "valid_from".to_owned(),
        ClaimValue::String("2026-01-01".to_owned()),
    );
    payload.insert(
        "valid_until".to_owned(),
        ClaimValue::String("2026-12-31".to_owned()),
    );
    payload.insert(
        "issuing_authority".to_owned(),
        ClaimValue::String("Tax Authority".to_owned()),
    );
    payload.insert(
        "issuing_country".to_owned(),
        ClaimValue::String("MT".to_owned()),
    );
    payload.insert(
        "expiry_date".to_owned(),
        ClaimValue::String("2027-07-13".to_owned()),
    );

    validate_claim_payload(&registry, &ClaimValue::Object(payload)).unwrap();
}

#[test]
fn eu_eaa_profile_validates_common_attestation_metadata() {
    let registry = eu_eaa_v1();

    validate_registry(&registry).unwrap();
    assert!(registry.claims.contains_key("attestation_type"));
    assert!(registry.claims.contains_key("location_status"));
    assert!(
        validate_disclosure(&registry, "/claims/attestation_id", DisclosureMode::Reveal).is_err()
    );
    assert!(validate_disclosure(&registry, "/claims/attestation_type", DisclosureMode::Eq).is_ok());

    let mut payload = BTreeMap::new();
    payload.insert(
        "subject_identifier".to_owned(),
        ClaimValue::String("subject-123".to_owned()),
    );
    payload.insert(
        "subject_family_name".to_owned(),
        ClaimValue::String("Doe".to_owned()),
    );
    payload.insert(
        "subject_given_name".to_owned(),
        ClaimValue::String("Alex".to_owned()),
    );
    payload.insert(
        "subject_birth_date".to_owned(),
        ClaimValue::String("1984-02-29".to_owned()),
    );
    payload.insert(
        "attestation_type".to_owned(),
        ClaimValue::String("generic-eaa".to_owned()),
    );
    payload.insert(
        "issuing_country".to_owned(),
        ClaimValue::String("MT".to_owned()),
    );
    payload.insert(
        "expiry_date".to_owned(),
        ClaimValue::String("2031-07-13".to_owned()),
    );

    validate_claim_payload(&registry, &ClaimValue::Object(payload)).unwrap();
}

#[test]
fn eu_driving_license_profile_validates_mdl_baseline() {
    let registry = eu_driving_license_v1();

    validate_registry(&registry).unwrap();
    assert!(registry.claims.contains_key("un_distinguishing_sign"));
    assert!(registry.claims.contains_key("driving_privileges"));
    assert!(
        validate_disclosure(&registry, "/claims/document_number", DisclosureMode::Reveal).is_err()
    );
    assert!(validate_disclosure(
        &registry,
        "/claims/un_distinguishing_sign",
        DisclosureMode::MemberOfSet
    )
    .is_ok());

    let mut payload = BTreeMap::new();
    payload.insert(
        "family_name".to_owned(),
        ClaimValue::String("Doe".to_owned()),
    );
    payload.insert(
        "given_name".to_owned(),
        ClaimValue::String("Alex".to_owned()),
    );
    payload.insert(
        "birth_date".to_owned(),
        ClaimValue::String("1984-02-29".to_owned()),
    );
    payload.insert(
        "issue_date".to_owned(),
        ClaimValue::String("2026-07-13".to_owned()),
    );
    payload.insert(
        "expiry_date".to_owned(),
        ClaimValue::String("2031-07-13".to_owned()),
    );
    payload.insert(
        "issuing_country".to_owned(),
        ClaimValue::String("MT".to_owned()),
    );
    payload.insert(
        "document_number".to_owned(),
        ClaimValue::String("DL123456".to_owned()),
    );
    payload.insert(
        "un_distinguishing_sign".to_owned(),
        ClaimValue::String("M".to_owned()),
    );
    payload.insert(
        "driving_privileges".to_owned(),
        ClaimValue::Array(Vec::new()),
    );

    validate_claim_payload(&registry, &ClaimValue::Object(payload)).unwrap();
}

#[test]
fn eu_diploma_profile_validates_learning_credential_baseline() {
    let registry = eu_diploma_v1();

    validate_registry(&registry).unwrap();
    assert!(registry.claims.contains_key("learning_achievement_title"));
    assert!(registry.claims.contains_key("qualification_level"));
    assert!(validate_disclosure(
        &registry,
        "/claims/learner_birth_date",
        DisclosureMode::Reveal
    )
    .is_err());
    assert!(validate_disclosure(
        &registry,
        "/claims/qualification_level",
        DisclosureMode::MemberOfSet
    )
    .is_ok());

    let mut payload = BTreeMap::new();
    payload.insert(
        "learner_family_name".to_owned(),
        ClaimValue::String("Doe".to_owned()),
    );
    payload.insert(
        "learner_given_name".to_owned(),
        ClaimValue::String("Alex".to_owned()),
    );
    payload.insert(
        "learner_birth_date".to_owned(),
        ClaimValue::String("1984-02-29".to_owned()),
    );
    payload.insert(
        "credential_title".to_owned(),
        ClaimValue::String("Bachelor of Science".to_owned()),
    );
    payload.insert(
        "awarding_body".to_owned(),
        ClaimValue::String("Example University".to_owned()),
    );
    payload.insert(
        "learning_achievement_title".to_owned(),
        ClaimValue::String("Computer Science".to_owned()),
    );
    payload.insert(
        "qualification_level".to_owned(),
        ClaimValue::String("EQF-6".to_owned()),
    );
    payload.insert(
        "awarded_date".to_owned(),
        ClaimValue::String("2026-07-13".to_owned()),
    );

    validate_claim_payload(&registry, &ClaimValue::Object(payload)).unwrap();
}

#[test]
fn eu_health_profile_validates_ehic_baseline() {
    let registry = eu_health_v1();

    validate_registry(&registry).unwrap();
    assert!(registry.claims.contains_key("competent_institution_id"));
    assert!(registry.claims.contains_key("card_number"));
    assert!(validate_disclosure(
        &registry,
        "/claims/personal_identification_number",
        DisclosureMode::Reveal
    )
    .is_err());
    assert!(validate_disclosure(&registry, "/claims/card_number", DisclosureMode::Eq).is_ok());

    let mut payload = BTreeMap::new();
    payload.insert(
        "family_name".to_owned(),
        ClaimValue::String("Doe".to_owned()),
    );
    payload.insert(
        "given_name".to_owned(),
        ClaimValue::String("Alex".to_owned()),
    );
    payload.insert(
        "personal_identification_number".to_owned(),
        ClaimValue::String("EHIC-PIN-123".to_owned()),
    );
    payload.insert(
        "birth_date".to_owned(),
        ClaimValue::String("1984-02-29".to_owned()),
    );
    payload.insert(
        "expiry_date".to_owned(),
        ClaimValue::String("2031-07-13".to_owned()),
    );
    payload.insert(
        "issuing_country".to_owned(),
        ClaimValue::String("MT".to_owned()),
    );
    payload.insert(
        "competent_institution_id".to_owned(),
        ClaimValue::String("MT001".to_owned()),
    );
    payload.insert(
        "competent_institution_acronym".to_owned(),
        ClaimValue::String("MT-HI".to_owned()),
    );
    payload.insert(
        "card_number".to_owned(),
        ClaimValue::String("EHIC-123456".to_owned()),
    );

    validate_claim_payload(&registry, &ClaimValue::Object(payload)).unwrap();
}

#[test]
fn eu_professional_license_profile_validates_common_license_baseline() {
    let registry = eu_professional_license_v1();

    validate_registry(&registry).unwrap();
    assert!(registry.claims.contains_key("profession"));
    assert!(registry.claims.contains_key("license_number"));
    assert!(
        validate_disclosure(&registry, "/claims/license_number", DisclosureMode::Reveal).is_err()
    );
    assert!(validate_disclosure(
        &registry,
        "/claims/professional_status",
        DisclosureMode::MemberOfSet
    )
    .is_ok());

    let mut payload = BTreeMap::new();
    payload.insert(
        "holder_family_name".to_owned(),
        ClaimValue::String("Doe".to_owned()),
    );
    payload.insert(
        "holder_given_name".to_owned(),
        ClaimValue::String("Alex".to_owned()),
    );
    payload.insert(
        "holder_birth_date".to_owned(),
        ClaimValue::String("1984-02-29".to_owned()),
    );
    payload.insert(
        "profession".to_owned(),
        ClaimValue::String("Engineer".to_owned()),
    );
    payload.insert(
        "license_number".to_owned(),
        ClaimValue::String("PRO-123456".to_owned()),
    );
    payload.insert(
        "competent_authority".to_owned(),
        ClaimValue::String("Professional Board".to_owned()),
    );
    payload.insert(
        "practice_jurisdiction".to_owned(),
        ClaimValue::String("MT".to_owned()),
    );
    payload.insert(
        "professional_status".to_owned(),
        ClaimValue::String("active".to_owned()),
    );

    validate_claim_payload(&registry, &ClaimValue::Object(payload)).unwrap();
}

#[test]
fn eu_eidas_vid_profile_reuses_pid_catalog() {
    let registry = eu_eidas_vid_v1();

    validate_registry(&registry).unwrap();
    assert_eq!(registry.claimset_id, "eu.eidas-vid.v1");
    assert_catalog_matches_registry(EU_EIDAS_VID_V1_CLAIM_IDS, &registry);
    assert_eq!(
        registry.claims.len(),
        eu_pid_v1().claims.len(),
        "eIDAS VID should stay aligned with the EU PID catalog"
    );
    assert!(validate_disclosure(
        &registry,
        "/claims/personal_administrative_number",
        DisclosureMode::Reveal
    )
    .is_err());
}

#[test]
fn eu_pid_profile_rejects_revealing_protected_identifiers() {
    let registry = eu_pid_v1();

    assert!(
        validate_disclosure(&registry, "/claims/document_number", DisclosureMode::Reveal).is_err()
    );
    assert!(validate_disclosure(
        &registry,
        "/claims/personal_administrative_number",
        DisclosureMode::Reveal
    )
    .is_err());
}

#[test]
fn passport_profile_rejects_revealing_protected_document_fields() {
    let registry = icao_passport_v1();

    assert!(
        validate_disclosure(&registry, "/claims/document_number", DisclosureMode::Reveal).is_err()
    );
    assert!(validate_disclosure(&registry, "/claims/face_image", DisclosureMode::Reveal).is_err());
    assert!(validate_disclosure(&registry, "/claims/mrz/line1", DisclosureMode::Reveal).is_err());
}

#[test]
fn eu_passport_profile_rejects_document_number_reveal() {
    let registry = eu_passport_v1();

    assert!(
        validate_disclosure(&registry, "/claims/document_number", DisclosureMode::Reveal).is_err()
    );
}

#[test]
fn eu_tax_profile_rejects_revealing_tax_identifier() {
    let registry = eu_tax_v1();

    assert!(
        validate_disclosure(&registry, "/claims/tax_identifier", DisclosureMode::Reveal).is_err()
    );
}

#[test]
fn eu_health_profile_rejects_revealing_personal_identification_number() {
    let registry = eu_health_v1();

    assert!(validate_disclosure(
        &registry,
        "/claims/personal_identification_number",
        DisclosureMode::Reveal
    )
    .is_err());
}

#[test]
fn eu_professional_license_profile_rejects_revealing_license_number() {
    let registry = eu_professional_license_v1();

    assert!(
        validate_disclosure(&registry, "/claims/license_number", DisclosureMode::Reveal).is_err()
    );
}

#[test]
fn eu_eidas_vid_profile_rejects_revealing_personal_administrative_number() {
    let registry = eu_eidas_vid_v1();

    assert!(validate_disclosure(
        &registry,
        "/claims/personal_administrative_number",
        DisclosureMode::Reveal
    )
    .is_err());
}

#[test]
fn passport_profile_validates_representative_payload() {
    let registry = icao_passport_v1();

    let mut chip_security = BTreeMap::new();
    chip_security.insert(
        "active_authentication".to_owned(),
        ClaimValue::Boolean(true),
    );
    let mut data_group_hashes = BTreeMap::new();
    data_group_hashes.insert("dg1".to_owned(), ClaimValue::Bytes(vec![0xA1; 32]));

    let mut payload = BTreeMap::new();
    payload.insert(
        "document_type".to_owned(),
        ClaimValue::String("P".to_owned()),
    );
    payload.insert(
        "document_code".to_owned(),
        ClaimValue::String("P".to_owned()),
    );
    payload.insert(
        "issuing_state".to_owned(),
        ClaimValue::String("MLT".to_owned()),
    );
    payload.insert(
        "issuing_state_or_organization".to_owned(),
        ClaimValue::String("MLT".to_owned()),
    );
    payload.insert(
        "family_name".to_owned(),
        ClaimValue::String("Doe".to_owned()),
    );
    payload.insert(
        "given_name".to_owned(),
        ClaimValue::String("Alex".to_owned()),
    );
    payload.insert(
        "primary_identifier".to_owned(),
        ClaimValue::String("Doe".to_owned()),
    );
    payload.insert(
        "secondary_identifier".to_owned(),
        ClaimValue::String("Alex".to_owned()),
    );
    payload.insert(
        "full_name".to_owned(),
        ClaimValue::String("Alex Doe".to_owned()),
    );
    payload.insert(
        "nationality".to_owned(),
        ClaimValue::String("MLT".to_owned()),
    );
    payload.insert(
        "date_of_birth".to_owned(),
        ClaimValue::String("1984-02-29".to_owned()),
    );
    payload.insert(
        "date_of_expiry".to_owned(),
        ClaimValue::String("2031-07-13".to_owned()),
    );
    payload.insert("sex".to_owned(), ClaimValue::String("X".to_owned()));
    payload.insert(
        "document_number".to_owned(),
        ClaimValue::String("P1234567".to_owned()),
    );
    payload.insert(
        "optional_data".to_owned(),
        ClaimValue::String("A1".to_owned()),
    );
    payload.insert(
        "optional_data_2".to_owned(),
        ClaimValue::String("B2".to_owned()),
    );
    let mut mrz = BTreeMap::new();
    mrz.insert(
        "line1".to_owned(),
        ClaimValue::String("P<MLTDOE<<ALEX<<<<<<<<<<<<<<<<<<<<<<<<".to_owned()),
    );
    mrz.insert(
        "line2".to_owned(),
        ClaimValue::String("P1234567<0MLT8402290X3107130A1<<<<<<<<<2".to_owned()),
    );
    mrz.insert("line3".to_owned(), ClaimValue::String("".to_owned()));
    mrz.insert(
        "document_number_check_digit".to_owned(),
        ClaimValue::String("0".to_owned()),
    );
    mrz.insert(
        "date_of_birth_check_digit".to_owned(),
        ClaimValue::String("0".to_owned()),
    );
    mrz.insert(
        "date_of_expiry_check_digit".to_owned(),
        ClaimValue::String("0".to_owned()),
    );
    mrz.insert(
        "composite_check_digit".to_owned(),
        ClaimValue::String("2".to_owned()),
    );
    payload.insert("mrz".to_owned(), ClaimValue::Object(mrz));
    payload.insert(
        "personal_number".to_owned(),
        ClaimValue::String("PN123456".to_owned()),
    );
    payload.insert(
        "issuing_authority".to_owned(),
        ClaimValue::String("Passport Office".to_owned()),
    );
    payload.insert(
        "date_of_issue".to_owned(),
        ClaimValue::String("2026-07-13".to_owned()),
    );
    payload.insert(
        "place_of_birth".to_owned(),
        ClaimValue::String("Valletta".to_owned()),
    );
    payload.insert(
        "permanent_address".to_owned(),
        ClaimValue::String("High Street 1, Valletta".to_owned()),
    );
    payload.insert(
        "telephone".to_owned(),
        ClaimValue::String("+35600000000".to_owned()),
    );
    payload.insert(
        "profession".to_owned(),
        ClaimValue::String("Engineer".to_owned()),
    );
    payload.insert("title".to_owned(), ClaimValue::String("Dr".to_owned()));
    payload.insert(
        "personal_summary".to_owned(),
        ClaimValue::String("Representative passport holder".to_owned()),
    );
    payload.insert(
        "other_names".to_owned(),
        ClaimValue::String("A. Doe".to_owned()),
    );
    payload.insert(
        "other_travel_document_numbers".to_owned(),
        ClaimValue::Array(vec![ClaimValue::String("T123".to_owned())]),
    );
    payload.insert(
        "endorsements".to_owned(),
        ClaimValue::String("None".to_owned()),
    );
    payload.insert(
        "tax_exit_requirements".to_owned(),
        ClaimValue::String("None".to_owned()),
    );
    payload.insert(
        "custody_information".to_owned(),
        ClaimValue::String("None".to_owned()),
    );
    payload.insert(
        "personalization_datetime".to_owned(),
        ClaimValue::String("2026-07-13T00:00:00Z".to_owned()),
    );
    payload.insert(
        "personalization_system_serial_number".to_owned(),
        ClaimValue::String("SYS123".to_owned()),
    );
    payload.insert("portrait".to_owned(), ClaimValue::Bytes(vec![1, 2, 3]));
    payload.insert("face_image".to_owned(), ClaimValue::Bytes(vec![1, 2, 3]));
    payload.insert(
        "signature_image".to_owned(),
        ClaimValue::Bytes(vec![4, 5, 6]),
    );
    payload.insert(
        "fingerprint_images".to_owned(),
        ClaimValue::Array(vec![ClaimValue::Bytes(vec![7, 8, 9])]),
    );
    payload.insert(
        "iris_images".to_owned(),
        ClaimValue::Array(vec![ClaimValue::Bytes(vec![10, 11, 12])]),
    );
    payload.insert(
        "displayed_portrait".to_owned(),
        ClaimValue::Bytes(vec![13, 14, 15]),
    );
    payload.insert(
        "displayed_signature".to_owned(),
        ClaimValue::Bytes(vec![16, 17, 18]),
    );
    payload.insert(
        "chip_security".to_owned(),
        ClaimValue::Object(chip_security),
    );
    payload.insert(
        "security_object_document".to_owned(),
        ClaimValue::Bytes(vec![0x30, 0x03, 0x01]),
    );
    payload.insert(
        "data_group_hashes".to_owned(),
        ClaimValue::Object(data_group_hashes),
    );
    payload.insert(
        "document_signer_certificate".to_owned(),
        ClaimValue::Bytes(vec![0x30, 0x03, 0x02]),
    );
    payload.insert(
        "active_authentication_public_key".to_owned(),
        ClaimValue::Bytes(vec![0x30, 0x03, 0x03]),
    );
    payload.insert(
        "chip_authentication_public_key".to_owned(),
        ClaimValue::Bytes(vec![0x30, 0x03, 0x04]),
    );
    let mut terminal_authentication_info = BTreeMap::new();
    terminal_authentication_info.insert("version".to_owned(), ClaimValue::String("1".to_owned()));
    payload.insert(
        "terminal_authentication_info".to_owned(),
        ClaimValue::Object(terminal_authentication_info),
    );

    validate_claim_payload(&registry, &ClaimValue::Object(payload)).unwrap();
}

fn assert_catalog_matches_registry(
    catalog: &[&str],
    registry: &reallyme_credential_claims::ClaimsRegistry,
) {
    assert_eq!(catalog.len(), registry.claims.len());
    for claim_id in catalog {
        assert!(
            registry.claims.contains_key(*claim_id),
            "missing {claim_id}"
        );
    }
}

fn assert_registry_contains_all(
    registry: &reallyme_credential_claims::ClaimsRegistry,
    claim_ids: &[&str],
) {
    for claim_id in claim_ids {
        assert!(
            registry.claims.contains_key(*claim_id),
            "registry {} is missing official claim {claim_id}",
            registry.claimset_id,
        );
    }
}

fn assert_source_map_covers_registry(
    registry: &reallyme_credential_claims::ClaimsRegistry,
    claim_ids: &[&str],
) {
    let source_fields = claim_ids.iter().copied().collect::<BTreeSet<_>>();
    for claim_id in registry.claims.keys() {
        assert!(
            source_fields.contains(claim_id.as_str()),
            "catalog source profile {} is missing registry claim {claim_id}",
            registry.claimset_id,
        );
    }
}

fn fields_from_source_profile(profile: &Value) -> Vec<&str> {
    profile["fields"]
        .as_array()
        .unwrap()
        .iter()
        .map(|field| field.as_str().unwrap())
        .collect()
}

fn assert_supported_catalog_coverage(coverage: &str) {
    assert!(
        matches!(
            coverage,
            "official-annex-field-set-with-normalization-aliases"
                | "official-annex-residence-contact-subset"
                | "alias-of-eu.pid.v1"
                | "derived-pid-presentation-profile"
                | "sector-baseline"
                | "preserve-only-alias"
                | "preserve-only-catalog"
        ),
        "unsupported catalog coverage {coverage}",
    );
}
