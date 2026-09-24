// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::collections::BTreeMap;

use crate::{
    ClaimDefinition, ClaimDisclosurePolicy, ClaimType, ClaimsRegistry, DisclosureMode,
    ENCODING_JCS_UTF8,
};

#[derive(Clone, Copy)]
pub(super) struct BuiltInClaim {
    pub(super) claim_id: &'static str,
    pub(super) claim_type: ClaimType,
    pub(super) allow_reveal: bool,
    pub(super) predicates: &'static [DisclosureMode],
}

pub(super) const NO_PREDICATES: &[DisclosureMode] = &[];
pub(super) const EQ: &[DisclosureMode] = &[DisclosureMode::Eq];
pub(super) const EQ_SET: &[DisclosureMode] = &[DisclosureMode::Eq, DisclosureMode::MemberOfSet];
pub(super) const ORDERED_RANGE: &[DisclosureMode] = &[
    DisclosureMode::Gte,
    DisclosureMode::Lte,
    DisclosureMode::Range,
];
pub(super) const AGE_RANGE: &[DisclosureMode] = &[DisclosureMode::Gte, DisclosureMode::Range];

/// Shared metadata fields for EUDI electronic attestations of attributes.
///
/// EAA schemas are sector-specific, but EUDI issuance and validation always
/// need a small envelope of issuer, validity, and status metadata. Keeping
/// those claims in one catalog prevents sector profiles from drifting on the
/// parts that verifiers compose across all attestations.
pub(super) const EAA_METADATA_CATALOG: &[BuiltInClaim] = &[
    claim("attestation_id", ClaimType::String, false, EQ),
    claim("attestation_type", ClaimType::String, true, EQ_SET),
    reveal("issuing_authority", ClaimType::String),
    claim("issuing_country", ClaimType::String, true, EQ_SET),
    claim("issuing_jurisdiction", ClaimType::String, true, EQ_SET),
    reveal("issuance_date", ClaimType::Date),
    reveal("expiry_date", ClaimType::Date),
    claim("document_number", ClaimType::String, false, EQ),
    claim("location_status", ClaimType::String, false, EQ),
    claim("authentic_source_id", ClaimType::String, false, EQ),
];

pub(super) const fn reveal(claim_id: &'static str, claim_type: ClaimType) -> BuiltInClaim {
    claim(claim_id, claim_type, true, NO_PREDICATES)
}

pub(super) const fn claim(
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

pub(super) fn registry_from_catalog(claimset_id: &str, catalog: &[BuiltInClaim]) -> ClaimsRegistry {
    registry_from_catalogs(claimset_id, &[catalog])
}

pub(super) fn eaa_registry_from_catalog(
    claimset_id: &str,
    catalog: &[BuiltInClaim],
) -> ClaimsRegistry {
    registry_from_catalogs(claimset_id, &[catalog, EAA_METADATA_CATALOG])
}

fn registry_from_catalogs(claimset_id: &str, catalogs: &[&[BuiltInClaim]]) -> ClaimsRegistry {
    let mut claims = BTreeMap::new();
    for catalog in catalogs {
        for claim in *catalog {
            claims.insert(
                claim.claim_id.to_owned(),
                ClaimDefinition {
                    claim_id: claim.claim_id.to_owned(),
                    claim_type: claim.claim_type,
                    encoding: ENCODING_JCS_UTF8.to_owned(),
                    disclosure: ClaimDisclosurePolicy {
                        allow_reveal: claim.allow_reveal,
                        predicates: claim.predicates.to_vec(),
                    },
                },
            );
        }
    }

    ClaimsRegistry {
        claimset_id: claimset_id.to_owned(),
        claims,
    }
}
