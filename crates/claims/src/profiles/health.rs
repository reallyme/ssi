// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::{ClaimType, ClaimsRegistry};

use super::common::{claim, eaa_registry_from_catalog, reveal, BuiltInClaim, EQ, EQ_SET};

/// Built-in EU health entitlement claim identifiers.
///
/// The reference interoperability baseline models European Health Insurance Card data. It does not
/// model medical records, diagnoses, prescriptions, or clinical observations;
/// those require a separate health-data profile and stricter consent policy.
pub const EU_HEALTH_V1_CLAIM_IDS: &[&str] = &[
    "family_name",
    "given_name",
    "personal_identification_number",
    "birth_date",
    "expiry_date",
    "issuing_country",
    "competent_institution_id",
    "competent_institution_acronym",
    "card_number",
    "attestation_id",
    "attestation_type",
    "issuing_authority",
    "issuing_jurisdiction",
    "issuance_date",
    "document_number",
    "location_status",
    "authentic_source_id",
];

/// EU health entitlement registry.
pub fn eu_health_v1() -> ClaimsRegistry {
    eaa_registry_from_catalog("eu.health.v1", EU_HEALTH_CATALOG)
}

const EU_HEALTH_CATALOG: &[BuiltInClaim] = &[
    reveal("family_name", ClaimType::String),
    reveal("given_name", ClaimType::String),
    claim(
        "personal_identification_number",
        ClaimType::String,
        false,
        EQ,
    ),
    claim("birth_date", ClaimType::Date, false, EQ),
    reveal("expiry_date", ClaimType::Date),
    claim("issuing_country", ClaimType::String, true, EQ_SET),
    claim("competent_institution_id", ClaimType::String, false, EQ),
    reveal("competent_institution_acronym", ClaimType::String),
    claim("card_number", ClaimType::String, false, EQ),
];
