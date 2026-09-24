// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::{ClaimType, ClaimsRegistry};

use super::common::{claim, registry_from_catalog, reveal, BuiltInClaim, EQ, EQ_SET};

/// Built-in EU address credential claim identifiers.
///
/// The catalog is a registry-backed subset of the natural-person PID address,
/// contact, and issuing metadata attributes defined for the European Digital
/// Identity Wallet PID profile. Address credentials frequently carry only this
/// residence slice, so keeping it first-class avoids duplicating PID semantics
/// in presentation policy code.
pub const EU_ADDRESS_V1_CLAIM_IDS: &[&str] = &[
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
];

/// EU address credential registry.
pub fn eu_address_v1() -> ClaimsRegistry {
    registry_from_catalog("eu.address.v1", EU_ADDRESS_CATALOG)
}

const EU_ADDRESS_CATALOG: &[BuiltInClaim] = &[
    reveal("resident_address/formatted", ClaimType::String),
    reveal("resident_address/street_address", ClaimType::String),
    reveal("resident_address/house_number", ClaimType::String),
    reveal("resident_address/locality", ClaimType::String),
    reveal("resident_address/region", ClaimType::String),
    reveal("resident_address/postal_code", ClaimType::String),
    claim("resident_address/country", ClaimType::String, true, EQ_SET),
    claim(
        "resident_address/country_subdivision",
        ClaimType::String,
        true,
        EQ_SET,
    ),
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
    claim("email_address", ClaimType::String, false, EQ),
    claim("mobile_phone_number", ClaimType::String, false, EQ),
    reveal("issuing_authority", ClaimType::String),
    claim("issuing_country", ClaimType::String, true, EQ_SET),
    claim("issuing_jurisdiction", ClaimType::String, true, EQ_SET),
    reveal("issuance_date", ClaimType::Date),
    reveal("expiry_date", ClaimType::Date),
    claim("document_number", ClaimType::String, false, EQ),
    claim("location_status", ClaimType::String, false, EQ),
];
