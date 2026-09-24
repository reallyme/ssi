// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::{ClaimType, ClaimsRegistry};

use super::common::{claim, registry_from_catalog, reveal, BuiltInClaim, EQ, EQ_SET};

/// Built-in EU tax credential claim identifiers.
///
/// The EU PID legal-person profile names VAT and tax reference identifiers.
/// This profile adds a narrow tax-residency envelope around those identifiers
/// so disclosure-policy consumers have a concrete registry for `eu.tax.v1`
/// without treating national tax attributes as complete or jurisdiction-final.
pub const EU_TAX_V1_CLAIM_IDS: &[&str] = &[
    "tax_identifier",
    "tax_reference_number",
    "vat_registration_number",
    "tax_residence_country",
    "tax_residence_jurisdiction",
    "tax_year",
    "valid_from",
    "valid_until",
    "issuing_authority",
    "issuing_country",
    "expiry_date",
    "document_number",
    "location_status",
];

/// EU tax credential registry.
pub fn eu_tax_v1() -> ClaimsRegistry {
    registry_from_catalog("eu.tax.v1", EU_TAX_CATALOG)
}

const EU_TAX_CATALOG: &[BuiltInClaim] = &[
    claim("tax_identifier", ClaimType::String, false, EQ),
    claim("tax_reference_number", ClaimType::String, false, EQ),
    claim("vat_registration_number", ClaimType::String, false, EQ),
    claim("tax_residence_country", ClaimType::String, true, EQ_SET),
    claim(
        "tax_residence_jurisdiction",
        ClaimType::String,
        true,
        EQ_SET,
    ),
    claim("tax_year", ClaimType::UnsignedInteger, true, EQ),
    reveal("valid_from", ClaimType::Date),
    reveal("valid_until", ClaimType::Date),
    reveal("issuing_authority", ClaimType::String),
    claim("issuing_country", ClaimType::String, true, EQ_SET),
    reveal("expiry_date", ClaimType::Date),
    claim("document_number", ClaimType::String, false, EQ),
    claim("location_status", ClaimType::String, false, EQ),
];
