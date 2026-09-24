// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::{ClaimType, ClaimsRegistry};

use super::common::{claim, eaa_registry_from_catalog, reveal, BuiltInClaim, EQ, EQ_SET};

/// Built-in EU diploma and learning credential claim identifiers.
///
/// This catalog is a compact ELM/EDCI interoperability baseline: it models the
/// learner, awarding body, learning achievement, qualification level, dates,
/// and common credential metadata without copying the full JSON-LD graph into
/// claim registry space.
pub const EU_DIPLOMA_V1_CLAIM_IDS: &[&str] = &[
    "learner_family_name",
    "learner_given_name",
    "learner_birth_date",
    "credential_title",
    "awarding_body",
    "learning_achievement_title",
    "qualification_level",
    "field_of_study",
    "awarded_date",
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

/// EU diploma and learning credential registry.
pub fn eu_diploma_v1() -> ClaimsRegistry {
    eaa_registry_from_catalog("eu.diploma.v1", EU_DIPLOMA_CATALOG)
}

const EU_DIPLOMA_CATALOG: &[BuiltInClaim] = &[
    reveal("learner_family_name", ClaimType::String),
    reveal("learner_given_name", ClaimType::String),
    claim("learner_birth_date", ClaimType::Date, false, EQ),
    reveal("credential_title", ClaimType::String),
    reveal("awarding_body", ClaimType::String),
    reveal("learning_achievement_title", ClaimType::String),
    claim("qualification_level", ClaimType::String, true, EQ_SET),
    claim("field_of_study", ClaimType::String, true, EQ_SET),
    reveal("awarded_date", ClaimType::Date),
    reveal("valid_from", ClaimType::Date),
];
