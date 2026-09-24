// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::collections::BTreeMap;

use crate::{
    ClaimDefinition, ClaimDisclosurePolicy, ClaimType, ClaimsRegistry, DisclosureMode,
    ENCODING_JCS_UTF8,
};

/// Built-in EU PID v1 claim identifiers covered by the starter catalog.
///
/// The catalog keeps stable ReallyMe claim IDs while tracking the EUDI PID data
/// categories used by ARF-style PID and mdoc/JWT-VC mappings. It is a hardened
/// built-in interoperability baseline, not a claim that every Member State must
/// issue every field.
pub const EU_PID_V1_CLAIM_IDS: &[&str] = &[
    "family_name",
    "given_name",
    "family_name_birth",
    "given_name_birth",
    "birth_date",
    "birthdate",
    "birth_place",
    "birth_country",
    "birth_state",
    "birth_city",
    "birth_family_name",
    "place_of_birth/locality",
    "place_of_birth/country",
    "nationality",
    "nationalities",
    "sex",
    "personal_administrative_number",
    "age",
    "age_in_years",
    "age_birth_year",
    "age_over_12",
    "age_over_13",
    "age_over_14",
    "age_over_16",
    "age_over_18",
    "age_over_21",
    "age_equal_or_over/~212",
    "age_equal_or_over/~214",
    "age_equal_or_over/~216",
    "age_equal_or_over/~218",
    "age_equal_or_over/~221",
    "age_equal_or_over/~265",
    "address/street_address",
    "address/locality",
    "address/postal_code",
    "address/country",
    "resident_address/formatted",
    "resident_address/street_address",
    "resident_address/house_number",
    "resident_address/locality",
    "resident_address/region",
    "resident_address/postal_code",
    "resident_address/country",
    "resident_address/country_subdivision",
    "resident_address/locator_designator",
    "resident_address/locator_name",
    "resident_address/po_box",
    "resident_address/thoroughfare",
    "resident_address/premise",
    "resident_address/administrative_area",
    "resident_address/post_name",
    "resident_country",
    "resident_state",
    "resident_city",
    "resident_postal_code",
    "resident_street",
    "resident_house_number",
    "email_address",
    "mobile_phone_number",
    "issuing_authority",
    "issuing_country",
    "issuing_jurisdiction",
    "issuance_date",
    "expiry_date",
    "document_number",
    "location_status",
    "portrait",
    "source_document_type",
    "source_document_number",
    "trust_anchor_id",
];

/// EU PID v1 claim registry.
pub fn eu_pid_v1() -> ClaimsRegistry {
    let mut claims = BTreeMap::new();
    for claim in EU_PID_CATALOG {
        insert_claim(
            &mut claims,
            claim.claim_id,
            claim.claim_type,
            claim.allow_reveal,
            claim.predicates,
        );
    }

    ClaimsRegistry {
        claimset_id: "eu.pid.v1".to_owned(),
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
const AGE_RANGE: &[DisclosureMode] = &[DisclosureMode::Gte, DisclosureMode::Range];

const EU_PID_CATALOG: &[BuiltInClaim] = &[
    reveal("family_name", ClaimType::String),
    reveal("given_name", ClaimType::String),
    reveal("family_name_birth", ClaimType::String),
    reveal("given_name_birth", ClaimType::String),
    claim("birth_date", ClaimType::Date, true, ORDERED_RANGE),
    claim("birthdate", ClaimType::Date, true, ORDERED_RANGE),
    reveal("birth_place", ClaimType::String),
    claim("birth_country", ClaimType::String, true, EQ_SET),
    reveal("birth_state", ClaimType::String),
    reveal("birth_city", ClaimType::String),
    reveal("birth_family_name", ClaimType::String),
    reveal("place_of_birth/locality", ClaimType::String),
    claim("place_of_birth/country", ClaimType::String, true, EQ_SET),
    claim("nationality", ClaimType::String, true, EQ_SET),
    claim("nationalities", ClaimType::Array, true, EQ_SET),
    claim("sex", ClaimType::UnsignedInteger, true, EQ_SET),
    claim(
        "personal_administrative_number",
        ClaimType::String,
        false,
        EQ,
    ),
    claim("age", ClaimType::UnsignedInteger, false, AGE_RANGE),
    claim("age_in_years", ClaimType::UnsignedInteger, false, AGE_RANGE),
    claim(
        "age_birth_year",
        ClaimType::UnsignedInteger,
        false,
        ORDERED_RANGE,
    ),
    claim("age_over_12", ClaimType::Boolean, false, EQ),
    claim("age_over_13", ClaimType::Boolean, false, EQ),
    claim("age_over_14", ClaimType::Boolean, false, EQ),
    claim("age_over_16", ClaimType::Boolean, false, EQ),
    claim("age_over_18", ClaimType::Boolean, false, EQ),
    claim("age_over_21", ClaimType::Boolean, false, EQ),
    claim("age_equal_or_over/~212", ClaimType::Boolean, false, EQ),
    claim("age_equal_or_over/~214", ClaimType::Boolean, false, EQ),
    claim("age_equal_or_over/~216", ClaimType::Boolean, false, EQ),
    claim("age_equal_or_over/~218", ClaimType::Boolean, false, EQ),
    claim("age_equal_or_over/~221", ClaimType::Boolean, false, EQ),
    claim("age_equal_or_over/~265", ClaimType::Boolean, false, EQ),
    reveal("address/street_address", ClaimType::String),
    reveal("address/locality", ClaimType::String),
    reveal("address/postal_code", ClaimType::String),
    claim("address/country", ClaimType::String, true, EQ_SET),
    reveal("resident_address/formatted", ClaimType::String),
    reveal("resident_address/street_address", ClaimType::String),
    reveal("resident_address/house_number", ClaimType::String),
    reveal("resident_address/locality", ClaimType::String),
    reveal("resident_address/region", ClaimType::String),
    reveal("resident_address/postal_code", ClaimType::String),
    claim("resident_address/country", ClaimType::String, true, EQ_SET),
    reveal("resident_address/country_subdivision", ClaimType::String),
    reveal("resident_address/locator_designator", ClaimType::String),
    reveal("resident_address/locator_name", ClaimType::String),
    reveal("resident_address/po_box", ClaimType::String),
    reveal("resident_address/thoroughfare", ClaimType::String),
    reveal("resident_address/premise", ClaimType::String),
    reveal("resident_address/administrative_area", ClaimType::String),
    reveal("resident_address/post_name", ClaimType::String),
    claim("resident_country", ClaimType::String, true, EQ_SET),
    reveal("resident_state", ClaimType::String),
    reveal("resident_city", ClaimType::String),
    reveal("resident_postal_code", ClaimType::String),
    reveal("resident_street", ClaimType::String),
    reveal("resident_house_number", ClaimType::String),
    claim("email_address", ClaimType::String, true, EQ),
    claim("mobile_phone_number", ClaimType::String, true, EQ),
    reveal("issuing_authority", ClaimType::String),
    claim("issuing_country", ClaimType::String, true, EQ_SET),
    claim("issuing_jurisdiction", ClaimType::String, true, EQ_SET),
    reveal("issuance_date", ClaimType::Date),
    claim("expiry_date", ClaimType::Date, true, ORDERED_RANGE),
    claim("document_number", ClaimType::String, false, EQ),
    claim("location_status", ClaimType::String, false, NO_PREDICATES),
    claim("portrait", ClaimType::Bytes, false, NO_PREDICATES),
    claim("source_document_type", ClaimType::String, false, EQ),
    claim("source_document_number", ClaimType::String, false, EQ),
    claim("trust_anchor_id", ClaimType::String, true, EQ),
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
