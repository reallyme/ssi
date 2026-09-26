// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(missing_docs, clippy::unwrap_used)]
//! Numeric claim typing and JSON number normalization coverage.

use std::collections::BTreeMap;

use reallyme_credential_claims::{
    claim_value_from_json_slice, validate_claim_payload, validate_claim_value, ClaimDecimal,
    ClaimDefinition, ClaimDisclosurePolicy, ClaimType, ClaimValue, ClaimsError,
    ClaimsInvalidReason, ClaimsRegistry, DisclosureMode, ENCODING_JCS_UTF8,
};

fn claim_definition(
    claim_id: &str,
    claim_type: ClaimType,
    allow_reveal: bool,
    predicates: Vec<DisclosureMode>,
) -> ClaimDefinition {
    ClaimDefinition {
        claim_id: claim_id.to_owned(),
        claim_type,
        encoding: ENCODING_JCS_UTF8.to_owned(),
        disclosure: ClaimDisclosurePolicy {
            allow_reveal,
            predicates,
        },
    }
}

fn age_registry() -> ClaimsRegistry {
    let mut claims = BTreeMap::new();
    claims.insert(
        "age".to_owned(),
        claim_definition("age", ClaimType::Integer, false, vec![DisclosureMode::Gte]),
    );
    claims.insert(
        "country".to_owned(),
        claim_definition("country", ClaimType::String, true, Vec::new()),
    );
    ClaimsRegistry {
        claimset_id: "eu.pid.v1".to_owned(),
        claims,
    }
}

#[test]
fn signed_integer_claims_accept_json_non_negative_integers() {
    let payload = claim_value_from_json_slice(br#"{"age":42,"country":"DE"}"#).unwrap();
    assert_eq!(validate_claim_payload(&age_registry(), &payload), Ok(()));

    for claim_type in [ClaimType::Integer, ClaimType::SignedInteger] {
        let definition = claim_definition("age", claim_type, true, Vec::new());
        assert_eq!(
            validate_claim_value(&definition, &ClaimValue::Unsigned(0)),
            Ok(())
        );
        assert_eq!(
            validate_claim_value(&definition, &ClaimValue::Unsigned(i64::MAX.unsigned_abs())),
            Ok(())
        );
        assert_eq!(
            validate_claim_value(&definition, &ClaimValue::Unsigned(u64::MAX)),
            Err(ClaimsError::InvalidInput(
                ClaimsInvalidReason::ClaimValueTypeMismatch
            ))
        );
    }
}

#[test]
fn unsigned_integer_claims_accept_only_non_negative_signed_values() {
    let definition = claim_definition("age", ClaimType::UnsignedInteger, true, Vec::new());
    assert_eq!(
        validate_claim_value(&definition, &ClaimValue::Signed(0)),
        Ok(())
    );
    assert_eq!(
        validate_claim_value(&definition, &ClaimValue::Signed(-1)),
        Err(ClaimsError::InvalidInput(
            ClaimsInvalidReason::ClaimValueTypeMismatch
        ))
    );
    assert_eq!(
        validate_claim_value(&definition, &ClaimValue::Signed(i64::MIN)),
        Err(ClaimsError::InvalidInput(
            ClaimsInvalidReason::ClaimValueTypeMismatch
        ))
    );
}

fn decimal_from_both_json_entry_points(input: &str) -> Result<ClaimValue, ClaimsError> {
    let from_slice = claim_value_from_json_slice(input.as_bytes());
    let parsed: serde_json::Value = serde_json::from_str(input).unwrap();
    let from_value = ClaimValue::from_json(&parsed);
    assert_eq!(from_slice, from_value, "entry points disagree for {input}");
    from_slice
}

#[test]
fn json_decimal_normalization_is_identical_across_entry_points() {
    for (input, expected) in [
        ("98.75", "98.75"),
        ("1.5", "1.5"),
        ("1.50", "1.5"),
        ("1e2", "100"),
        ("100.0", "100"),
        ("-0.125", "-0.125"),
        ("1e-7", "0.0000001"),
        ("123456789012.345", "123456789012.345"),
    ] {
        assert_eq!(
            decimal_from_both_json_entry_points(input),
            Ok(ClaimValue::Decimal(ClaimDecimal::new(expected).unwrap())),
            "input {input}"
        );
    }
}

#[test]
fn json_decimal_normalization_rejects_non_exact_representations() {
    for input in [
        "0.30000000000000004",
        "1.0000000000000002",
        "18446744073709551616",
        "1e300",
        "-0.0",
    ] {
        assert_eq!(
            decimal_from_both_json_entry_points(input),
            Err(ClaimsError::InvalidInput(
                ClaimsInvalidReason::InvalidDecimal
            )),
            "input {input}"
        );
    }
}
