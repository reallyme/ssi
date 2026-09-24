// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::collections::BTreeMap;

use crate::{
    ClaimDefinition, ClaimDisclosurePolicy, ClaimType, ClaimsRegistry, DisclosureMode,
    ENCODING_JCS_UTF8,
};

/// Built-in ICAO passport v1 claim identifiers covered by the starter catalog.
///
/// This catalog covers MRZ-facing fields plus common LDS data-group concepts
/// used by passport verification and travel-credential mappings. Sensitive
/// biometric, document-number, and chip-security fields are predicate-only or
/// non-reveal by default.
pub const ICAO_PASSPORT_V1_CLAIM_IDS: &[&str] = &[
    "document_type",
    "document_code",
    "issuing_state",
    "issuing_state_or_organization",
    "family_name",
    "given_name",
    "primary_identifier",
    "secondary_identifier",
    "full_name",
    "nationality",
    "date_of_birth",
    "date_of_expiry",
    "sex",
    "document_number",
    "personal_number",
    "optional_data",
    "optional_data_2",
    "mrz/line1",
    "mrz/line2",
    "mrz/line3",
    "mrz/document_number_check_digit",
    "mrz/date_of_birth_check_digit",
    "mrz/date_of_expiry_check_digit",
    "mrz/composite_check_digit",
    "issuing_authority",
    "date_of_issue",
    "place_of_birth",
    "permanent_address",
    "telephone",
    "profession",
    "title",
    "personal_summary",
    "other_names",
    "other_travel_document_numbers",
    "endorsements",
    "tax_exit_requirements",
    "custody_information",
    "personalization_datetime",
    "personalization_system_serial_number",
    "portrait",
    "face_image",
    "signature_image",
    "fingerprint_images",
    "iris_images",
    "displayed_portrait",
    "displayed_signature",
    "chip_security",
    "security_object_document",
    "data_group_hashes",
    "document_signer_certificate",
    "active_authentication_public_key",
    "chip_authentication_public_key",
    "terminal_authentication_info",
];

/// EU passport claim identifiers.
///
/// The EU-facing claimset reuses the same ICAO 9303 travel-document catalog.
/// Keeping this alias explicit lets disclosure-policy select `eu.passport.v1`
/// while preserving the provenance of the underlying passport claim semantics.
pub const EU_PASSPORT_V1_CLAIM_IDS: &[&str] = ICAO_PASSPORT_V1_CLAIM_IDS;

/// ICAO 9303 passport claim registry.
pub fn icao_passport_v1() -> ClaimsRegistry {
    passport_registry("icao.passport.v1")
}

/// EU passport claim registry backed by ICAO 9303 passport semantics.
pub fn eu_passport_v1() -> ClaimsRegistry {
    passport_registry("eu.passport.v1")
}

fn passport_registry(claimset_id: &str) -> ClaimsRegistry {
    let mut claims = BTreeMap::new();
    for claim in ICAO_PASSPORT_CATALOG {
        insert_claim(
            &mut claims,
            claim.claim_id,
            claim.claim_type,
            claim.allow_reveal,
            claim.predicates,
        );
    }

    ClaimsRegistry {
        claimset_id: claimset_id.to_owned(),
        claims,
    }
}

#[derive(Clone, Copy)]
struct BuiltInClaim {
    claim_id: &'static str,
    claim_type: ClaimType,
    allow_reveal: bool,
    predicates: &'static [DisclosureMode],
}

const NO_PREDICATES: &[DisclosureMode] = &[];
const EQ: &[DisclosureMode] = &[DisclosureMode::Eq];
const EQ_SET: &[DisclosureMode] = &[DisclosureMode::Eq, DisclosureMode::MemberOfSet];
const ORDERED_RANGE: &[DisclosureMode] = &[
    DisclosureMode::Gte,
    DisclosureMode::Lte,
    DisclosureMode::Range,
];

const ICAO_PASSPORT_CATALOG: &[BuiltInClaim] = &[
    reveal("document_type", ClaimType::String),
    reveal("document_code", ClaimType::String),
    claim("issuing_state", ClaimType::String, true, EQ_SET),
    claim(
        "issuing_state_or_organization",
        ClaimType::String,
        true,
        EQ_SET,
    ),
    reveal("family_name", ClaimType::String),
    reveal("given_name", ClaimType::String),
    reveal("primary_identifier", ClaimType::String),
    reveal("secondary_identifier", ClaimType::String),
    reveal("full_name", ClaimType::String),
    claim("nationality", ClaimType::String, true, EQ_SET),
    claim("date_of_birth", ClaimType::Date, false, ORDERED_RANGE),
    claim("date_of_expiry", ClaimType::Date, true, ORDERED_RANGE),
    claim("sex", ClaimType::String, true, EQ_SET),
    claim("document_number", ClaimType::String, false, EQ),
    claim("personal_number", ClaimType::String, false, EQ),
    claim("optional_data", ClaimType::String, false, EQ),
    claim("optional_data_2", ClaimType::String, false, EQ),
    claim("mrz/line1", ClaimType::String, false, EQ),
    claim("mrz/line2", ClaimType::String, false, EQ),
    claim("mrz/line3", ClaimType::String, false, EQ),
    claim(
        "mrz/document_number_check_digit",
        ClaimType::String,
        false,
        EQ,
    ),
    claim(
        "mrz/date_of_birth_check_digit",
        ClaimType::String,
        false,
        EQ,
    ),
    claim(
        "mrz/date_of_expiry_check_digit",
        ClaimType::String,
        false,
        EQ,
    ),
    claim("mrz/composite_check_digit", ClaimType::String, false, EQ),
    reveal("issuing_authority", ClaimType::String),
    reveal("date_of_issue", ClaimType::Date),
    reveal("place_of_birth", ClaimType::String),
    reveal("permanent_address", ClaimType::String),
    reveal("telephone", ClaimType::String),
    reveal("profession", ClaimType::String),
    reveal("title", ClaimType::String),
    reveal("personal_summary", ClaimType::String),
    reveal("other_names", ClaimType::String),
    claim(
        "other_travel_document_numbers",
        ClaimType::Array,
        false,
        NO_PREDICATES,
    ),
    reveal("endorsements", ClaimType::String),
    reveal("tax_exit_requirements", ClaimType::String),
    reveal("custody_information", ClaimType::String),
    reveal("personalization_datetime", ClaimType::DateTime),
    reveal("personalization_system_serial_number", ClaimType::String),
    claim("portrait", ClaimType::Bytes, false, NO_PREDICATES),
    claim("face_image", ClaimType::Bytes, false, NO_PREDICATES),
    claim("signature_image", ClaimType::Bytes, false, NO_PREDICATES),
    claim("fingerprint_images", ClaimType::Array, false, NO_PREDICATES),
    claim("iris_images", ClaimType::Array, false, NO_PREDICATES),
    claim("displayed_portrait", ClaimType::Bytes, false, NO_PREDICATES),
    claim(
        "displayed_signature",
        ClaimType::Bytes,
        false,
        NO_PREDICATES,
    ),
    claim("chip_security", ClaimType::Object, false, NO_PREDICATES),
    claim(
        "security_object_document",
        ClaimType::Bytes,
        false,
        NO_PREDICATES,
    ),
    claim("data_group_hashes", ClaimType::Object, false, NO_PREDICATES),
    claim(
        "document_signer_certificate",
        ClaimType::Bytes,
        false,
        NO_PREDICATES,
    ),
    claim(
        "active_authentication_public_key",
        ClaimType::Bytes,
        false,
        NO_PREDICATES,
    ),
    claim(
        "chip_authentication_public_key",
        ClaimType::Bytes,
        false,
        NO_PREDICATES,
    ),
    claim(
        "terminal_authentication_info",
        ClaimType::Object,
        false,
        NO_PREDICATES,
    ),
];

const fn reveal(claim_id: &'static str, claim_type: ClaimType) -> BuiltInClaim {
    claim(claim_id, claim_type, true, NO_PREDICATES)
}

const fn claim(
    claim_id: &'static str,
    claim_type: ClaimType,
    allow_reveal: bool,
    predicates: &'static [DisclosureMode],
) -> BuiltInClaim {
    BuiltInClaim {
        claim_id,
        claim_type,
        allow_reveal,
        predicates,
    }
}

fn insert_claim(
    claims: &mut BTreeMap<String, ClaimDefinition>,
    claim_id: &str,
    claim_type: ClaimType,
    allow_reveal: bool,
    predicates: &[DisclosureMode],
) {
    claims.insert(
        claim_id.to_owned(),
        ClaimDefinition {
            claim_id: claim_id.to_owned(),
            claim_type,
            encoding: ENCODING_JCS_UTF8.to_owned(),
            disclosure: ClaimDisclosurePolicy {
                allow_reveal,
                predicates: predicates.to_vec(),
            },
        },
    );
}
