// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::{ClaimType, ClaimsRegistry};

use super::common::{
    claim, eaa_registry_from_catalog, reveal, BuiltInClaim, EQ, EQ_SET, NO_PREDICATES,
};

/// Built-in EU driving licence claim identifiers.
///
/// The catalog follows the ISO/IEC 18013-5 mDL vocabulary used by EUDI
/// proximity presentation. Detailed category entitlements remain a structured
/// `driving_privileges` claim; verifier policy can later project
/// category-specific paths once a credential profile selects that representation.
pub const EU_DRIVING_LICENSE_V1_CLAIM_IDS: &[&str] = &[
    "family_name",
    "given_name",
    "birth_date",
    "issue_date",
    "expiry_date",
    "issuing_country",
    "issuing_authority",
    "document_number",
    "portrait",
    "un_distinguishing_sign",
    "driving_privileges",
    "attestation_id",
    "attestation_type",
    "issuing_jurisdiction",
    "issuance_date",
    "location_status",
    "authentic_source_id",
];

/// EU driving licence registry.
pub fn eu_driving_license_v1() -> ClaimsRegistry {
    eaa_registry_from_catalog("eu.driving_license.v1", EU_DRIVING_LICENSE_CATALOG)
}

const EU_DRIVING_LICENSE_CATALOG: &[BuiltInClaim] = &[
    reveal("family_name", ClaimType::String),
    reveal("given_name", ClaimType::String),
    claim("birth_date", ClaimType::Date, false, EQ),
    reveal("issue_date", ClaimType::Date),
    reveal("expiry_date", ClaimType::Date),
    claim("issuing_country", ClaimType::String, true, EQ_SET),
    reveal("issuing_authority", ClaimType::String),
    claim("document_number", ClaimType::String, false, EQ),
    claim("portrait", ClaimType::Bytes, false, NO_PREDICATES),
    claim("un_distinguishing_sign", ClaimType::String, true, EQ_SET),
    claim("driving_privileges", ClaimType::Array, false, NO_PREDICATES),
];
