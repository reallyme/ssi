// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![no_main]

use libfuzzer_sys::fuzz_target;
use reallyme_credential_claims::{
    claim_value_from_json_slice, validate_claim_payload, ClaimDefinition, ClaimDisclosurePolicy,
    ClaimType, ClaimsRegistry, DisclosureMode, ENCODING_JCS_UTF8,
};
use std::collections::BTreeMap;

const MAX_FUZZ_INPUT_BYTES: usize = 8192;

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_FUZZ_INPUT_BYTES {
        return;
    }

    let Ok(payload) = claim_value_from_json_slice(data) else {
        return;
    };

    let registry = fuzz_registry();
    let _ = validate_claim_payload(&registry, &payload);
});

fn fuzz_registry() -> ClaimsRegistry {
    let mut claims = BTreeMap::new();
    insert_claim(&mut claims, "family_name", ClaimType::String);
    insert_claim(&mut claims, "given_name", ClaimType::String);
    insert_claim(&mut claims, "birthdate", ClaimType::Date);
    insert_claim(&mut claims, "age", ClaimType::UnsignedInteger);
    insert_claim(&mut claims, "age_equal_or_over/~218", ClaimType::Boolean);
    insert_claim(&mut claims, "address/street_address", ClaimType::String);
    insert_claim(&mut claims, "address/locality", ClaimType::String);
    insert_claim(&mut claims, "address/postal_code", ClaimType::String);
    insert_claim(&mut claims, "address/country", ClaimType::String);
    insert_claim(&mut claims, "nationalities", ClaimType::Array);
    insert_claim(&mut claims, "portrait", ClaimType::Bytes);
    insert_claim(&mut claims, "updated_at", ClaimType::DateTime);

    ClaimsRegistry {
        claimset_id: "claims.fuzz.v1".to_owned(),
        claims,
    }
}

fn insert_claim(
    claims: &mut BTreeMap<String, ClaimDefinition>,
    claim_id: &str,
    claim_type: ClaimType,
) {
    claims.insert(
        claim_id.to_owned(),
        ClaimDefinition {
            claim_id: claim_id.to_owned(),
            claim_type,
            encoding: ENCODING_JCS_UTF8.to_owned(),
            disclosure: ClaimDisclosurePolicy {
                allow_reveal: true,
                predicates: vec![DisclosureMode::Eq],
            },
        },
    );
}
