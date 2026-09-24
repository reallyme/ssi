// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::{ClaimType, ClaimsRegistry};

use super::common::{eaa_registry_from_catalog, reveal, BuiltInClaim};

/// Built-in generic EU electronic attestation of attributes claim identifiers.
///
/// This profile is intentionally metadata-heavy. Sector EAAs add their own
/// subject matter claims, but wallet relying parties still need stable issuer,
/// status, and validity fields before sector-specific validation can run.
pub const EU_EAA_V1_CLAIM_IDS: &[&str] = &[
    "subject_identifier",
    "subject_family_name",
    "subject_given_name",
    "subject_birth_date",
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

/// EU generic EAA registry.
pub fn eu_eaa_v1() -> ClaimsRegistry {
    eaa_registry_from_catalog("eu.eaa.v1", EU_EAA_CATALOG)
}

const EU_EAA_CATALOG: &[BuiltInClaim] = &[
    reveal("subject_identifier", ClaimType::String),
    reveal("subject_family_name", ClaimType::String),
    reveal("subject_given_name", ClaimType::String),
    reveal("subject_birth_date", ClaimType::Date),
];
