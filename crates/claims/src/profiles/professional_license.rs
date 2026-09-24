// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::{ClaimType, ClaimsRegistry};

use super::common::{claim, eaa_registry_from_catalog, reveal, BuiltInClaim, EQ, EQ_SET};

/// Built-in EU professional licence claim identifiers.
///
/// This profile covers the common professional-certification shape described by
/// the European Learning Model and by EAA sector usage: holder identity,
/// profession, competent authority, licence number, scope, jurisdiction,
/// status, and validity. Sector-specific regulated-profession schemas can
/// extend this once their authoritative catalogs are pinned.
pub const EU_PROFESSIONAL_LICENSE_V1_CLAIM_IDS: &[&str] = &[
    "holder_family_name",
    "holder_given_name",
    "holder_birth_date",
    "profession",
    "professional_title",
    "license_number",
    "competent_authority",
    "registration_number",
    "practice_jurisdiction",
    "practice_scope",
    "professional_status",
    "valid_from",
    "attestation_id",
    "attestation_type",
    "issuing_authority",
    "issuing_country",
    "issuing_jurisdiction",
    "issuance_date",
    "expiry_date",
    "document_number",
    "location_status",
    "authentic_source_id",
];

/// EU professional licence registry.
pub fn eu_professional_license_v1() -> ClaimsRegistry {
    eaa_registry_from_catalog(
        "eu.professional_license.v1",
        EU_PROFESSIONAL_LICENSE_CATALOG,
    )
}

const EU_PROFESSIONAL_LICENSE_CATALOG: &[BuiltInClaim] = &[
    reveal("holder_family_name", ClaimType::String),
    reveal("holder_given_name", ClaimType::String),
    claim("holder_birth_date", ClaimType::Date, false, EQ),
    reveal("profession", ClaimType::String),
    reveal("professional_title", ClaimType::String),
    claim("license_number", ClaimType::String, false, EQ),
    reveal("competent_authority", ClaimType::String),
    claim("registration_number", ClaimType::String, false, EQ),
    claim("practice_jurisdiction", ClaimType::String, true, EQ_SET),
    reveal("practice_scope", ClaimType::String),
    claim("professional_status", ClaimType::String, true, EQ_SET),
    reveal("valid_from", ClaimType::Date),
];
