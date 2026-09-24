// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::collections::{BTreeMap, BTreeSet};

use reallyme_credential_claims::{
    profiles::{
        eu_address_v1, eu_age_v1, eu_company_v1, eu_diploma_v1, eu_driving_license_v1, eu_eaa_v1,
        eu_eidas_vid_v1, eu_health_v1, eu_passport_v1, eu_pid_v1, eu_professional_license_v1,
        eu_tax_v1, icao_passport_v1, EU_ADDRESS_V1_CLAIM_IDS, EU_AGE_V1_CLAIM_IDS,
        EU_COMPANY_V1_CLAIM_IDS, EU_DIPLOMA_V1_CLAIM_IDS, EU_DRIVING_LICENSE_V1_CLAIM_IDS,
        EU_EAA_V1_CLAIM_IDS, EU_EIDAS_VID_V1_CLAIM_IDS, EU_HEALTH_V1_CLAIM_IDS,
        EU_PASSPORT_V1_CLAIM_IDS, EU_PID_V1_CLAIM_IDS, EU_PROFESSIONAL_LICENSE_V1_CLAIM_IDS,
        EU_TAX_V1_CLAIM_IDS, ICAO_PASSPORT_V1_CLAIM_IDS,
    },
    validate_claim_payload, validate_disclosure, validate_registry, ClaimValue, DisclosureMode,
};
use serde_json::Value;

const CLAIMS_CATALOG_SOURCES: &str = include_str!("../../../../vectors/claims/catalog-sources.json");

#[test]
fn predefined_registry_catalogs_cover_policy_claimsets() {
    let cases = [
        ("eu.pid.v1", eu_pid_v1(), EU_PID_V1_CLAIM_IDS),
        ("eu.eaa.v1", eu_eaa_v1(), EU_EAA_V1_CLAIM_IDS),
        ("eu.age.v1", eu_age_v1(), EU_AGE_V1_CLAIM_IDS),
        ("eu.address.v1", eu_address_v1(), EU_ADDRESS_V1_CLAIM_IDS),
        ("eu.diploma.v1", eu_diploma_v1(), EU_DIPLOMA_V1_CLAIM_IDS),
        (
            "eu.driving_license.v1",
            eu_driving_license_v1(),
            EU_DRIVING_LICENSE_V1_CLAIM_IDS,
        ),
        (
            "eu.professional_license.v1",
            eu_professional_license_v1(),
            EU_PROFESSIONAL_LICENSE_V1_CLAIM_IDS,
        ),
        ("eu.health.v1", eu_health_v1(), EU_HEALTH_V1_CLAIM_IDS),
        ("eu.company.v1", eu_company_v1(), EU_COMPANY_V1_CLAIM_IDS),
        ("eu.tax.v1", eu_tax_v1(), EU_TAX_V1_CLAIM_IDS),
        (
            "eu.eidas-vid.v1",
            eu_eidas_vid_v1(),
            EU_EIDAS_VID_V1_CLAIM_IDS,
        ),
        ("eu.passport.v1", eu_passport_v1(), EU_PASSPORT_V1_CLAIM_IDS),
        (
            "icao.passport.v1",
            icao_passport_v1(),
            ICAO_PASSPORT_V1_CLAIM_IDS,
        ),
    ];

    for (claimset_id, registry, catalog) in cases {
        validate_registry(&registry).unwrap();
        assert_eq!(registry.claimset_id, claimset_id);
        assert_catalog_matches_registry(catalog, &registry);
    }
}

#[test]
fn predefined_catalog_source_map_matches_registries() {
    let source_map: Value = serde_json::from_str(CLAIMS_CATALOG_SOURCES).unwrap();
    assert_eq!(
        source_map["official_sector_catalog_assessment"]["status"].as_str(),
        Some("catalogue-process-established-no-populated-sector-field-catalog-pinned"),
    );
    let mut mapped_claimsets = BTreeSet::new();
    for profile in source_map["profiles"].as_array().unwrap() {
        let claimset_id = profile["claimset_id"].as_str().unwrap();
        assert!(
            mapped_claimsets.insert(claimset_id),
            "duplicate catalog source profile {claimset_id}",
        );
        let registry = registry_for_predefined_claimset(claimset_id);
        assert!(
            registry.is_some(),
            "unexpected catalog source profile {claimset_id}",
        );
        let registry = registry.unwrap();

        assert!(
            profile["source"].as_str().is_some(),
            "catalog source profile {claimset_id} is missing source",
        );
        let coverage = profile["coverage"].as_str();
        assert!(
            coverage.is_some(),
            "catalog source profile {claimset_id} is missing coverage",
        );
        assert_supported_catalog_coverage(coverage.unwrap());

        let fields = fields_from_source_profile(profile);
        assert_registry_contains_all(&registry, fields.as_slice());
        assert_source_map_covers_registry(&registry, fields.as_slice());
    }

    let expected_claimsets = [
        "eu.pid.v1",
        "eu.eaa.v1",
        "eu.age.v1",
        "eu.address.v1",
        "eu.diploma.v1",
        "eu.driving_license.v1",
        "eu.professional_license.v1",
        "eu.health.v1",
        "eu.company.v1",
        "eu.tax.v1",
        "eu.eidas-vid.v1",
        "eu.passport.v1",
        "icao.passport.v1",
    ];
    for claimset_id in expected_claimsets {
        assert!(
            mapped_claimsets.contains(claimset_id),
            "missing catalog source profile {claimset_id}",
        );
    }
}

#[test]
fn eu_pid_profile_validates_and_supports_age_predicate() {
    let registry = eu_pid_v1();

    validate_registry(&registry).unwrap();
    assert_catalog_matches_registry(EU_PID_V1_CLAIM_IDS, &registry);
    assert!(registry.claims.contains_key("birth_date"));
    assert!(registry.claims.contains_key("birthdate"));
    assert!(registry
        .claims
        .contains_key("resident_address/street_address"));
    assert!(registry.claims.contains_key("address/street_address"));
    assert!(registry.claims.contains_key("age_equal_or_over/~218"));
    assert!(registry.claims.contains_key("resident_address/formatted"));
    assert!(registry
        .claims
        .contains_key("personal_administrative_number"));
    assert!(registry.claims.contains_key("age_over_21"));
    assert!(registry.claims.contains_key("document_number"));
    assert!(registry.claims.contains_key("location_status"));
    assert!(validate_disclosure(&registry, "/claims/age", DisclosureMode::Gte).is_ok());
    assert!(validate_disclosure(&registry, "/claims/age", DisclosureMode::Reveal).is_err());
    assert!(validate_disclosure(&registry, "/claims/age_over_18", DisclosureMode::Eq).is_ok());
    assert!(validate_disclosure(&registry, "/claims/age_over_21", DisclosureMode::Eq).is_ok());
    assert!(validate_disclosure(
        &registry,
        "/claims/age_equal_or_over/~218",
        DisclosureMode::Eq
    )
    .is_ok());
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
fn eu_pid_profile_covers_eu_2024_2977_annex_pid_fields() {
    let registry = eu_pid_v1();

    assert_registry_contains_all(
        &registry,
        &[
            "family_name",
            "given_name",
            "birth_date",
            "birth_place",
            "nationality",
            "resident_address/formatted",
            "resident_country",
            "resident_state",
            "resident_city",
            "resident_postal_code",
            "resident_street",
            "resident_house_number",
            "personal_administrative_number",
            "portrait",
            "family_name_birth",
            "given_name_birth",
            "sex",
            "email_address",
            "mobile_phone_number",
            "expiry_date",
            "issuing_authority",
            "issuing_country",
            "document_number",
            "issuing_jurisdiction",
            "location_status",
        ],
    );
}

#[test]
fn eu_pid_profile_validates_arf_sd_jwt_payload_shape() {
    let registry = eu_pid_v1();

    let mut address = BTreeMap::new();
    address.insert(
        "street_address".to_owned(),
        ClaimValue::String("Heidestrasse 17".to_owned()),
    );
    address.insert(
        "locality".to_owned(),
        ClaimValue::String("Koeln".to_owned()),
    );
    address.insert(
        "postal_code".to_owned(),
        ClaimValue::String("51147".to_owned()),
    );
    address.insert("country".to_owned(), ClaimValue::String("DE".to_owned()));

    let mut place_of_birth = BTreeMap::new();
    place_of_birth.insert(
        "locality".to_owned(),
        ClaimValue::String("Berlin".to_owned()),
    );
    place_of_birth.insert("country".to_owned(), ClaimValue::String("DE".to_owned()));

    let mut age_equal_or_over = BTreeMap::new();
    age_equal_or_over.insert("12".to_owned(), ClaimValue::Boolean(true));
    age_equal_or_over.insert("14".to_owned(), ClaimValue::Boolean(true));
    age_equal_or_over.insert("16".to_owned(), ClaimValue::Boolean(true));
    age_equal_or_over.insert("18".to_owned(), ClaimValue::Boolean(true));
    age_equal_or_over.insert("21".to_owned(), ClaimValue::Boolean(true));
    age_equal_or_over.insert("65".to_owned(), ClaimValue::Boolean(false));

    let mut payload = BTreeMap::new();
    payload.insert(
        "given_name".to_owned(),
        ClaimValue::String("Erika".to_owned()),
    );
    payload.insert(
        "family_name".to_owned(),
        ClaimValue::String("Mustermann".to_owned()),
    );
    payload.insert(
        "birthdate".to_owned(),
        ClaimValue::String("1963-08-12".to_owned()),
    );
    payload.insert("address".to_owned(), ClaimValue::Object(address));
    payload.insert(
        "nationalities".to_owned(),
        ClaimValue::Array(vec![ClaimValue::String("DE".to_owned())]),
    );
    payload.insert("sex".to_owned(), ClaimValue::Unsigned(2));
    payload.insert(
        "birth_family_name".to_owned(),
        ClaimValue::String("Gabler".to_owned()),
    );
    payload.insert(
        "place_of_birth".to_owned(),
        ClaimValue::Object(place_of_birth),
    );
    payload.insert(
        "age_equal_or_over".to_owned(),
        ClaimValue::Object(age_equal_or_over),
    );
    payload.insert("age_in_years".to_owned(), ClaimValue::Unsigned(62));
    payload.insert("age_birth_year".to_owned(), ClaimValue::Unsigned(1963));
    payload.insert(
        "issuance_date".to_owned(),
        ClaimValue::String("2020-03-11".to_owned()),
    );
    payload.insert(
        "expiry_date".to_owned(),
        ClaimValue::String("2030-03-12".to_owned()),
    );
    payload.insert(
        "issuing_authority".to_owned(),
        ClaimValue::String("DE".to_owned()),
    );
    payload.insert(
        "issuing_country".to_owned(),
        ClaimValue::String("DE".to_owned()),
    );

    validate_claim_payload(&registry, &ClaimValue::Object(payload)).unwrap();
}

#[test]
fn eu_pid_profile_validates_representative_payload() {
    let registry = eu_pid_v1();

    let mut resident_address = BTreeMap::new();
    resident_address.insert(
        "formatted".to_owned(),
        ClaimValue::String("High Street 1, VLT 1111 Valletta, MT".to_owned()),
    );
    resident_address.insert(
        "street_address".to_owned(),
        ClaimValue::String("High Street 1".to_owned()),
    );
    resident_address.insert(
        "house_number".to_owned(),
        ClaimValue::String("1".to_owned()),
    );
    resident_address.insert(
        "locality".to_owned(),
        ClaimValue::String("Valletta".to_owned()),
    );
    resident_address.insert("region".to_owned(), ClaimValue::String("MT".to_owned()));
    resident_address.insert(
        "postal_code".to_owned(),
        ClaimValue::String("VLT 1111".to_owned()),
    );
    resident_address.insert("country".to_owned(), ClaimValue::String("MT".to_owned()));
    resident_address.insert(
        "country_subdivision".to_owned(),
        ClaimValue::String("MT-60".to_owned()),
    );
    resident_address.insert(
        "locator_designator".to_owned(),
        ClaimValue::String("1".to_owned()),
    );
    resident_address.insert(
        "locator_name".to_owned(),
        ClaimValue::String("High Street".to_owned()),
    );
    resident_address.insert("po_box".to_owned(), ClaimValue::String("PO123".to_owned()));
    resident_address.insert(
        "thoroughfare".to_owned(),
        ClaimValue::String("High Street".to_owned()),
    );
    resident_address.insert(
        "premise".to_owned(),
        ClaimValue::String("Apartment 2".to_owned()),
    );
    resident_address.insert(
        "administrative_area".to_owned(),
        ClaimValue::String("Valletta".to_owned()),
    );
    resident_address.insert(
        "post_name".to_owned(),
        ClaimValue::String("Valletta".to_owned()),
    );

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
        "family_name_birth".to_owned(),
        ClaimValue::String("Doe".to_owned()),
    );
    payload.insert(
        "given_name_birth".to_owned(),
        ClaimValue::String("Alex".to_owned()),
    );
    payload.insert(
        "birth_date".to_owned(),
        ClaimValue::String("1984-02-29".to_owned()),
    );
    payload.insert(
        "birth_place".to_owned(),
        ClaimValue::String("Valletta".to_owned()),
    );
    payload.insert(
        "birth_country".to_owned(),
        ClaimValue::String("MT".to_owned()),
    );
    payload.insert(
        "birth_state".to_owned(),
        ClaimValue::String("MT".to_owned()),
    );
    payload.insert(
        "birth_city".to_owned(),
        ClaimValue::String("Valletta".to_owned()),
    );
    payload.insert(
        "nationality".to_owned(),
        ClaimValue::String("MT".to_owned()),
    );
    payload.insert("sex".to_owned(), ClaimValue::Unsigned(0));
    payload.insert(
        "personal_administrative_number".to_owned(),
        ClaimValue::String("MT-PAN-123456".to_owned()),
    );
    payload.insert("age".to_owned(), ClaimValue::Unsigned(42));
    payload.insert("age_over_18".to_owned(), ClaimValue::Boolean(true));
    payload.insert("age_over_12".to_owned(), ClaimValue::Boolean(true));
    payload.insert("age_over_13".to_owned(), ClaimValue::Boolean(true));
    payload.insert("age_over_14".to_owned(), ClaimValue::Boolean(true));
    payload.insert("age_over_16".to_owned(), ClaimValue::Boolean(true));
    payload.insert("age_over_21".to_owned(), ClaimValue::Boolean(true));
    payload.insert("age_in_years".to_owned(), ClaimValue::Unsigned(42));
    payload.insert("age_birth_year".to_owned(), ClaimValue::Unsigned(1984));
    payload.insert(
        "resident_address".to_owned(),
        ClaimValue::Object(resident_address),
    );
    payload.insert(
        "resident_country".to_owned(),
        ClaimValue::String("MT".to_owned()),
    );
    payload.insert(
        "resident_state".to_owned(),
        ClaimValue::String("MT".to_owned()),
    );
    payload.insert(
        "resident_city".to_owned(),
        ClaimValue::String("Valletta".to_owned()),
    );
    payload.insert(
        "resident_postal_code".to_owned(),
        ClaimValue::String("VLT 1111".to_owned()),
    );
    payload.insert(
        "resident_street".to_owned(),
        ClaimValue::String("High Street".to_owned()),
    );
    payload.insert(
        "resident_house_number".to_owned(),
        ClaimValue::String("1".to_owned()),
    );
    payload.insert(
        "email_address".to_owned(),
        ClaimValue::String("alex@example.invalid".to_owned()),
    );
    payload.insert(
        "mobile_phone_number".to_owned(),
        ClaimValue::String("+35600000000".to_owned()),
    );
    payload.insert(
        "issuing_authority".to_owned(),
        ClaimValue::String("Identity Authority".to_owned()),
    );
    payload.insert(
        "issuing_country".to_owned(),
        ClaimValue::String("MT".to_owned()),
    );
    payload.insert(
        "issuing_jurisdiction".to_owned(),
        ClaimValue::String("MT".to_owned()),
    );
    payload.insert(
        "issuance_date".to_owned(),
        ClaimValue::String("2026-07-13".to_owned()),
    );
    payload.insert(
        "expiry_date".to_owned(),
        ClaimValue::String("2031-07-13".to_owned()),
    );
    payload.insert(
        "document_number".to_owned(),
        ClaimValue::String("PID123456".to_owned()),
    );
    payload.insert(
        "location_status".to_owned(),
        ClaimValue::String("https://status.example.invalid/pid/PID123456".to_owned()),
    );
    payload.insert("portrait".to_owned(), ClaimValue::Bytes(vec![1, 2, 3]));
    payload.insert(
        "source_document_type".to_owned(),
        ClaimValue::String("national-id-card".to_owned()),
    );
    payload.insert(
        "source_document_number".to_owned(),
        ClaimValue::String("ID123456".to_owned()),
    );
    payload.insert(
        "trust_anchor_id".to_owned(),
        ClaimValue::String("EU:MT:PID:ROOT".to_owned()),
    );

    validate_claim_payload(&registry, &ClaimValue::Object(payload)).unwrap();
}

#[test]
fn passport_profile_validates_and_protects_document_number() {
    let registry = icao_passport_v1();

    validate_registry(&registry).unwrap();
    assert_catalog_matches_registry(ICAO_PASSPORT_V1_CLAIM_IDS, &registry);
    assert!(registry.claims.contains_key("document_number"));
    assert!(registry.claims.contains_key("mrz/line1"));
    assert!(registry.claims.contains_key("security_object_document"));
    assert!(registry
        .claims
        .contains_key("active_authentication_public_key"));
    assert!(
        validate_disclosure(&registry, "/claims/document_number", DisclosureMode::Reveal).is_err()
    );
    assert!(validate_disclosure(&registry, "/claims/document_number", DisclosureMode::Eq).is_ok());
    assert!(validate_disclosure(&registry, "/claims/face_image", DisclosureMode::Reveal).is_err());
    assert!(validate_disclosure(&registry, "/claims/mrz/line1", DisclosureMode::Reveal).is_err());
}

#[test]
fn eu_passport_profile_alias_matches_policy_claimset() {
    let registry = eu_passport_v1();

    validate_registry(&registry).unwrap();
    assert_eq!(registry.claimset_id, "eu.passport.v1");
    assert_catalog_matches_registry(EU_PASSPORT_V1_CLAIM_IDS, &registry);
    assert_eq!(
        registry.claims.len(),
        icao_passport_v1().claims.len(),
        "EU passport should stay aligned with the ICAO passport catalog"
    );
    assert!(
        validate_disclosure(&registry, "/claims/document_number", DisclosureMode::Reveal).is_err()
    );
    assert!(validate_disclosure(&registry, "/claims/document_number", DisclosureMode::Eq).is_ok());
}

#[test]
fn eu_address_profile_matches_pid_address_subset() {
    let registry = eu_address_v1();

    validate_registry(&registry).unwrap();
    assert!(registry.claims.contains_key("resident_address/formatted"));
    assert!(registry.claims.contains_key("resident_address/country"));
    assert!(registry.claims.contains_key("email_address"));
    assert!(validate_disclosure(
        &registry,
        "/claims/resident_address/country",
        DisclosureMode::MemberOfSet
    )
    .is_ok());
    assert!(
        validate_disclosure(&registry, "/claims/email_address", DisclosureMode::Reveal).is_err()
    );

    let mut resident_address = BTreeMap::new();
    resident_address.insert(
        "formatted".to_owned(),
        ClaimValue::String("High Street 1, VLT 1111 Valletta, MT".to_owned()),
    );
    resident_address.insert(
        "street_address".to_owned(),
        ClaimValue::String("High Street".to_owned()),
    );
    resident_address.insert(
        "house_number".to_owned(),
        ClaimValue::String("1".to_owned()),
    );
    resident_address.insert(
        "locality".to_owned(),
        ClaimValue::String("Valletta".to_owned()),
    );
    resident_address.insert("region".to_owned(), ClaimValue::String("MT".to_owned()));
    resident_address.insert(
        "postal_code".to_owned(),
        ClaimValue::String("VLT 1111".to_owned()),
    );
    resident_address.insert("country".to_owned(), ClaimValue::String("MT".to_owned()));
    resident_address.insert(
        "country_subdivision".to_owned(),
        ClaimValue::String("MT-60".to_owned()),
    );

    let mut payload = BTreeMap::new();
    payload.insert(
        "resident_address".to_owned(),
        ClaimValue::Object(resident_address),
    );
    payload.insert(
        "resident_country".to_owned(),
        ClaimValue::String("MT".to_owned()),
    );
    payload.insert(
        "resident_city".to_owned(),
        ClaimValue::String("Valletta".to_owned()),
    );
    payload.insert(
        "email_address".to_owned(),
        ClaimValue::String("alex@example.invalid".to_owned()),
    );
    payload.insert(
        "mobile_phone_number".to_owned(),
        ClaimValue::String("+35600000000".to_owned()),
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
fn eu_company_profile_matches_legal_person_pid_subset() {
    let registry = eu_company_v1();

    validate_registry(&registry).unwrap();
    assert!(registry.claims.contains_key("current_legal_name"));
    assert!(registry.claims.contains_key("legal_person_identifier"));
    assert!(registry.claims.contains_key("vat_registration_number"));
    assert!(registry.claims.contains_key("legal_entity_identifier"));
    assert!(registry
        .claims
        .contains_key("economic_operator_registration_and_identification"));
    assert!(validate_disclosure(
        &registry,
        "/claims/tax_reference_number",
        DisclosureMode::Reveal
    )
    .is_err());
    assert!(validate_disclosure(
        &registry,
        "/claims/legal_entity_identifier",
        DisclosureMode::Eq
    )
    .is_ok());

    let mut current_address = BTreeMap::new();
    current_address.insert(
        "formatted".to_owned(),
        ClaimValue::String("Example House, Valletta, MT".to_owned()),
    );
    current_address.insert("country".to_owned(), ClaimValue::String("MT".to_owned()));

    let mut payload = BTreeMap::new();
    payload.insert(
        "current_legal_name".to_owned(),
        ClaimValue::String("Example Limited".to_owned()),
    );
    payload.insert(
        "legal_person_identifier".to_owned(),
        ClaimValue::String("MT-REG-123456".to_owned()),
    );
    payload.insert(
        "current_address".to_owned(),
        ClaimValue::Object(current_address),
    );
    payload.insert(
        "vat_registration_number".to_owned(),
        ClaimValue::String("MT12345678".to_owned()),
    );
    payload.insert(
        "legal_entity_identifier".to_owned(),
        ClaimValue::String("5493001KJTIIGC8Y1R12".to_owned()),
    );
    payload.insert(
        "issuing_authority".to_owned(),
        ClaimValue::String("Business Registry".to_owned()),
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
fn eu_company_profile_covers_eu_2024_2977_annex_legal_person_fields() {
    let registry = eu_company_v1();

    assert_registry_contains_all(
        &registry,
        &[
            "current_legal_name",
            "legal_person_identifier",
            "current_address/formatted",
            "vat_registration_number",
            "tax_reference_number",
            "european_unique_identifier",
            "legal_entity_identifier",
            "economic_operator_registration_and_identification",
            "excise_number",
        ],
    );
}
