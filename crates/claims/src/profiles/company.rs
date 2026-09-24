// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::{ClaimType, ClaimsRegistry};

use super::common::{claim, registry_from_catalog, reveal, BuiltInClaim, EQ, EQ_SET};

/// Built-in EU company credential claim identifiers.
///
/// The catalog tracks the legal-person PID attributes in the European Digital
/// Identity Wallet PID implementing regulation: current legal name, a unique
/// legal-person identifier, current address, common tax and business registry
/// identifiers, and issuing metadata.
pub const EU_COMPANY_V1_CLAIM_IDS: &[&str] = &[
    "current_legal_name",
    "legal_person_identifier",
    "current_address/formatted",
    "current_address/street_address",
    "current_address/house_number",
    "current_address/locality",
    "current_address/region",
    "current_address/postal_code",
    "current_address/country",
    "vat_registration_number",
    "tax_reference_number",
    "european_unique_identifier",
    "legal_entity_identifier",
    "economic_operator_registration_and_identification",
    "excise_number",
    "issuing_authority",
    "issuing_country",
    "issuing_jurisdiction",
    "issuance_date",
    "expiry_date",
    "document_number",
    "location_status",
];

/// EU company credential registry.
pub fn eu_company_v1() -> ClaimsRegistry {
    registry_from_catalog("eu.company.v1", EU_COMPANY_CATALOG)
}

const EU_COMPANY_CATALOG: &[BuiltInClaim] = &[
    reveal("current_legal_name", ClaimType::String),
    claim("legal_person_identifier", ClaimType::String, true, EQ),
    reveal("current_address/formatted", ClaimType::String),
    reveal("current_address/street_address", ClaimType::String),
    reveal("current_address/house_number", ClaimType::String),
    reveal("current_address/locality", ClaimType::String),
    reveal("current_address/region", ClaimType::String),
    reveal("current_address/postal_code", ClaimType::String),
    claim("current_address/country", ClaimType::String, true, EQ_SET),
    claim("vat_registration_number", ClaimType::String, true, EQ),
    claim("tax_reference_number", ClaimType::String, false, EQ),
    claim("european_unique_identifier", ClaimType::String, true, EQ),
    claim("legal_entity_identifier", ClaimType::String, true, EQ),
    claim(
        "economic_operator_registration_and_identification",
        ClaimType::String,
        true,
        EQ,
    ),
    claim("excise_number", ClaimType::String, false, EQ),
    reveal("issuing_authority", ClaimType::String),
    claim("issuing_country", ClaimType::String, true, EQ_SET),
    claim("issuing_jurisdiction", ClaimType::String, true, EQ_SET),
    reveal("issuance_date", ClaimType::Date),
    reveal("expiry_date", ClaimType::Date),
    claim("document_number", ClaimType::String, false, EQ),
    claim("location_status", ClaimType::String, false, EQ),
];
