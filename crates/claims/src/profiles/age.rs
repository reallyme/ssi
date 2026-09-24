// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::{ClaimType, ClaimsRegistry};

use super::common::{claim, registry_from_catalog, BuiltInClaim, AGE_RANGE, EQ, ORDERED_RANGE};

/// Built-in EU age credential claim identifiers.
///
/// This catalog is a focused subset of EU PID age-related fields for
/// pseudonymous age and age-over presentations.
pub const EU_AGE_V1_CLAIM_IDS: &[&str] = &[
    "age",
    "age_in_years",
    "age_birth_year",
    "birth_date",
    "age_over_12",
    "age_over_13",
    "age_over_14",
    "age_over_16",
    "age_over_18",
    "age_over_21",
];

/// EU age credential registry.
pub fn eu_age_v1() -> ClaimsRegistry {
    registry_from_catalog("eu.age.v1", EU_AGE_CATALOG)
}

const EU_AGE_CATALOG: &[BuiltInClaim] = &[
    claim("age", ClaimType::UnsignedInteger, false, AGE_RANGE),
    claim("age_in_years", ClaimType::UnsignedInteger, false, AGE_RANGE),
    claim(
        "age_birth_year",
        ClaimType::UnsignedInteger,
        false,
        ORDERED_RANGE,
    ),
    claim("birth_date", ClaimType::Date, false, ORDERED_RANGE),
    claim("age_over_12", ClaimType::Boolean, false, EQ),
    claim("age_over_13", ClaimType::Boolean, false, EQ),
    claim("age_over_14", ClaimType::Boolean, false, EQ),
    claim("age_over_16", ClaimType::Boolean, false, EQ),
    claim("age_over_18", ClaimType::Boolean, false, EQ),
    claim("age_over_21", ClaimType::Boolean, false, EQ),
];
