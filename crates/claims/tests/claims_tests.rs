// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(missing_docs, clippy::unwrap_used)]
//! Test coverage for this crate.

use std::collections::BTreeMap;

use reallyme_credential_claims::{
    claim_id_from_path, claim_path, claim_value_from_json_slice, claim_value_from_path_entries,
    escape_field_segment, parse_claim_path, resolve_claim_path, validate_claim_payload,
    validate_claim_value, validate_disclosure, validate_registry, ClaimDate, ClaimDateTime,
    ClaimDecimal, ClaimDefinition, ClaimDisclosurePolicy, ClaimPathEntry, ClaimPathSegment,
    ClaimType, ClaimValue, ClaimsError, ClaimsInvalidReason, ClaimsRegistry, DisclosureMode,
    ENCODING_JCS_UTF8, MAX_CLAIMS_PER_REGISTRY, MAX_CLAIM_ID_BYTES, MAX_CLAIM_PATH_DEPTH,
    MAX_CLAIM_PATH_SEGMENT_BYTES, MAX_CLAIM_VALUE_DEPTH, MAX_DISCLOSURE_PREDICATES,
};

fn sample_registry() -> ClaimsRegistry {
    let mut claims = BTreeMap::new();
    claims.insert(
        "age".to_owned(),
        ClaimDefinition {
            claim_id: "age".to_owned(),
            claim_type: ClaimType::Integer,
            encoding: ENCODING_JCS_UTF8.to_owned(),
            disclosure: ClaimDisclosurePolicy {
                allow_reveal: false,
                predicates: vec![DisclosureMode::Gte, DisclosureMode::Range],
            },
        },
    );
    claims.insert(
        "country".to_owned(),
        ClaimDefinition {
            claim_id: "country".to_owned(),
            claim_type: ClaimType::String,
            encoding: ENCODING_JCS_UTF8.to_owned(),
            disclosure: ClaimDisclosurePolicy {
                allow_reveal: true,
                predicates: Vec::new(),
            },
        },
    );

    ClaimsRegistry {
        claimset_id: "claims.test.v1".to_owned(),
        claims,
    }
}

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

fn nested_registry() -> ClaimsRegistry {
    let mut claims = BTreeMap::new();
    for (claim_id, claim_type) in [
        ("address/street~1name", ClaimType::String),
        ("children/0/name", ClaimType::String),
        ("children/0/age", ClaimType::UnsignedInteger),
        ("age_equal_or_over/~218", ClaimType::Boolean),
        ("age", ClaimType::UnsignedInteger),
        ("active", ClaimType::Boolean),
        ("birth_date", ClaimType::Date),
        ("updated_at", ClaimType::DateTime),
        ("score", ClaimType::Decimal),
        ("portrait", ClaimType::Bytes),
        ("middle_name", ClaimType::Null),
        ("tags", ClaimType::Array),
    ] {
        claims.insert(
            claim_id.to_owned(),
            claim_definition(claim_id, claim_type, true, Vec::new()),
        );
    }

    ClaimsRegistry {
        claimset_id: "claims.nested.v1".to_owned(),
        claims,
    }
}

#[test]
fn canonical_claim_paths_roundtrip() {
    let path = claim_path("age").unwrap();

    assert_eq!(path, "/claims/age");
    assert_eq!(claim_id_from_path(&path), Some("age"));
    assert_eq!(claim_id_from_path("/bad/age"), None);
}

#[test]
fn nested_claim_paths_support_escaping_and_array_selectors() {
    let path = parse_claim_path("/claims/address/street~1name").unwrap();

    assert_eq!(path.claim_id().as_deref(), Some("address/street~1name"));
    assert_eq!(
        path.segments(),
        &[
            ClaimPathSegment::Field("address".to_owned()),
            ClaimPathSegment::Field("street/name".to_owned())
        ]
    );

    let array_path = parse_claim_path("/claims/children/0/name").unwrap();
    assert_eq!(
        array_path.segments(),
        &[
            ClaimPathSegment::Field("children".to_owned()),
            ClaimPathSegment::ArrayIndex(0),
            ClaimPathSegment::Field("name".to_owned())
        ]
    );

    assert_eq!(escape_field_segment("18"), "~218");
    let numeric_field_path = parse_claim_path("/claims/age_equal_or_over/~218").unwrap();
    assert_eq!(
        numeric_field_path.claim_id().as_deref(),
        Some("age_equal_or_over/~218")
    );
    assert_eq!(
        numeric_field_path.segments(),
        &[
            ClaimPathSegment::Field("age_equal_or_over".to_owned()),
            ClaimPathSegment::Field("18".to_owned())
        ]
    );
}

#[test]
fn claim_paths_reject_wildcards_and_ambiguous_segments() {
    assert_eq!(
        parse_claim_path("/claims/address/*"),
        Err(ClaimsError::InvalidInput(
            ClaimsInvalidReason::WildcardClaimPathNotAllowed
        ))
    );
    assert_eq!(
        parse_claim_path("/claims/0/name"),
        Err(ClaimsError::InvalidInput(
            ClaimsInvalidReason::InvalidClaimPathSegment
        ))
    );
    assert_eq!(
        parse_claim_path("/claims/address/01"),
        Err(ClaimsError::InvalidInput(
            ClaimsInvalidReason::InvalidClaimPathSegment
        ))
    );
    assert_eq!(
        parse_claim_path("/claims/address/bad~2escape"),
        Err(ClaimsError::InvalidInput(
            ClaimsInvalidReason::InvalidClaimPathSegment
        ))
    );
    assert_eq!(
        parse_claim_path("/claims/address/~2"),
        Err(ClaimsError::InvalidInput(
            ClaimsInvalidReason::InvalidClaimPathSegment
        ))
    );
}

#[test]
fn disclosure_reveal_and_predicate_rules_are_enforced() {
    let registry = sample_registry();

    assert!(validate_disclosure(&registry, "/claims/country", DisclosureMode::Reveal).is_ok());
    assert_eq!(
        validate_disclosure(&registry, "/claims/age", DisclosureMode::Reveal),
        Err(ClaimsError::DisclosureNotAllowed)
    );
    assert!(validate_disclosure(&registry, "/claims/age", DisclosureMode::Gte).is_ok());
    assert_eq!(
        validate_disclosure(&registry, "/claims/country", DisclosureMode::Gte),
        Err(ClaimsError::PredicateNotAllowed)
    );
}

#[test]
fn invalid_disclosure_modes_are_rejected() {
    let registry = sample_registry();

    assert_eq!(
        validate_disclosure(&registry, "/claims/country", DisclosureMode::Unspecified),
        Err(ClaimsError::InvalidInput(
            ClaimsInvalidReason::InvalidDisclosureMode
        ))
    );
    assert_eq!(
        validate_disclosure(&registry, "/claims/country", DisclosureMode::Hidden),
        Err(ClaimsError::InvalidInput(
            ClaimsInvalidReason::InvalidDisclosureMode
        ))
    );
}

#[test]
fn disclosure_rejects_unknown_claim_path() {
    let registry = sample_registry();

    assert_eq!(
        validate_disclosure(&registry, "/claims/unknown", DisclosureMode::Reveal),
        Err(ClaimsError::UnknownClaim)
    );
}

#[test]
fn registry_rejects_key_mismatch() {
    let mut registry = sample_registry();
    let mut age = registry.claims.remove("age").unwrap();
    age.claim_id = "other".to_owned();
    registry.claims.insert("age".to_owned(), age);

    assert_eq!(
        validate_registry(&registry),
        Err(ClaimsError::InvalidInput(
            ClaimsInvalidReason::ClaimKeyMismatch
        ))
    );
}

#[test]
fn registry_rejects_bad_predicate_entries() {
    let mut registry = sample_registry();
    registry
        .claims
        .get_mut("age")
        .unwrap()
        .disclosure
        .predicates
        .push(DisclosureMode::Reveal);

    assert_eq!(
        validate_registry(&registry),
        Err(ClaimsError::InvalidInput(
            ClaimsInvalidReason::InvalidDisclosureMode
        ))
    );
}

#[test]
fn registry_rejects_parent_child_claim_conflicts() {
    let mut claims = BTreeMap::new();
    claims.insert(
        "address".to_owned(),
        claim_definition("address", ClaimType::Object, true, Vec::new()),
    );
    claims.insert(
        "address/street".to_owned(),
        claim_definition("address/street", ClaimType::String, true, Vec::new()),
    );

    let registry = ClaimsRegistry {
        claimset_id: "claims.conflict.v1".to_owned(),
        claims,
    };

    assert_eq!(
        validate_registry(&registry),
        Err(ClaimsError::InvalidInput(
            ClaimsInvalidReason::ParentChildClaimPathConflict
        ))
    );
}

#[test]
fn registry_rejects_too_many_claims() {
    let mut claims = BTreeMap::new();
    for index in 0..=MAX_CLAIMS_PER_REGISTRY {
        let claim_id = format!("claim{index}");
        claims.insert(
            claim_id.clone(),
            ClaimDefinition {
                claim_id,
                claim_type: ClaimType::String,
                encoding: ENCODING_JCS_UTF8.to_owned(),
                disclosure: ClaimDisclosurePolicy {
                    allow_reveal: true,
                    predicates: Vec::new(),
                },
            },
        );
    }
    let registry = ClaimsRegistry {
        claimset_id: "claims.test.v1".to_owned(),
        claims,
    };

    assert_eq!(
        validate_registry(&registry),
        Err(ClaimsError::InvalidInput(
            ClaimsInvalidReason::TooManyClaims
        ))
    );
}

#[test]
fn registry_rejects_oversized_claim_id() {
    let mut registry = sample_registry();
    let claim_id = "a".repeat(MAX_CLAIM_ID_BYTES + 1);
    registry.claims.insert(
        claim_id.clone(),
        ClaimDefinition {
            claim_id,
            claim_type: ClaimType::String,
            encoding: ENCODING_JCS_UTF8.to_owned(),
            disclosure: ClaimDisclosurePolicy {
                allow_reveal: true,
                predicates: Vec::new(),
            },
        },
    );

    assert_eq!(
        validate_registry(&registry),
        Err(ClaimsError::InvalidInput(
            ClaimsInvalidReason::ClaimIdTooLong
        ))
    );
}

#[test]
fn registry_rejects_too_many_predicates() {
    let mut registry = sample_registry();
    registry
        .claims
        .get_mut("age")
        .unwrap()
        .disclosure
        .predicates = vec![DisclosureMode::Gte; MAX_DISCLOSURE_PREDICATES + 1];

    assert_eq!(
        validate_registry(&registry),
        Err(ClaimsError::InvalidInput(
            ClaimsInvalidReason::TooManyPredicates
        ))
    );
}

#[test]
fn claim_payload_validates_nested_values_against_definitions() {
    let registry = nested_registry();
    let mut child = BTreeMap::new();
    child.insert("name".to_owned(), ClaimValue::String("Alex".to_owned()));
    child.insert("age".to_owned(), ClaimValue::Unsigned(9));

    let mut address = BTreeMap::new();
    address.insert(
        "street/name".to_owned(),
        ClaimValue::String("High Street".to_owned()),
    );

    let mut age_equal_or_over = BTreeMap::new();
    age_equal_or_over.insert("18".to_owned(), ClaimValue::Boolean(true));

    let mut root = BTreeMap::new();
    root.insert("address".to_owned(), ClaimValue::Object(address));
    root.insert(
        "age_equal_or_over".to_owned(),
        ClaimValue::Object(age_equal_or_over),
    );
    root.insert(
        "children".to_owned(),
        ClaimValue::Array(vec![ClaimValue::Object(child)]),
    );
    root.insert("age".to_owned(), ClaimValue::Unsigned(42));
    root.insert("active".to_owned(), ClaimValue::Boolean(true));
    root.insert(
        "birth_date".to_owned(),
        ClaimValue::String("1984-02-29".to_owned()),
    );
    root.insert(
        "updated_at".to_owned(),
        ClaimValue::String("2026-07-13T10:15:30Z".to_owned()),
    );
    root.insert(
        "score".to_owned(),
        ClaimValue::Decimal(ClaimDecimal::new("98.75").unwrap()),
    );
    root.insert("portrait".to_owned(), ClaimValue::Bytes(vec![1, 2, 3, 4]));
    root.insert("middle_name".to_owned(), ClaimValue::Null);
    root.insert(
        "tags".to_owned(),
        ClaimValue::Array(vec![ClaimValue::String("verified".to_owned())]),
    );

    assert!(validate_claim_payload(&registry, &ClaimValue::Object(root)).is_ok());
}

#[test]
fn claim_payload_accepts_empty_containers_and_numeric_boundaries() {
    let mut claims = BTreeMap::new();
    for (claim_id, claim_type) in [
        ("empty_object", ClaimType::Object),
        ("empty_array", ClaimType::Array),
        ("signed_min", ClaimType::SignedInteger),
        ("unsigned_max", ClaimType::UnsignedInteger),
        ("updated_at", ClaimType::DateTime),
        ("updated_at_fractional", ClaimType::DateTime),
    ] {
        claims.insert(
            claim_id.to_owned(),
            claim_definition(claim_id, claim_type, true, Vec::new()),
        );
    }
    let registry = ClaimsRegistry {
        claimset_id: "claims.boundaries.v1".to_owned(),
        claims,
    };

    let mut root = BTreeMap::new();
    root.insert(
        "empty_object".to_owned(),
        ClaimValue::Object(BTreeMap::new()),
    );
    root.insert("empty_array".to_owned(), ClaimValue::Array(Vec::new()));
    root.insert("signed_min".to_owned(), ClaimValue::Signed(i64::MIN));
    root.insert("unsigned_max".to_owned(), ClaimValue::Unsigned(u64::MAX));
    root.insert(
        "updated_at".to_owned(),
        ClaimValue::String("2026-07-13T11:15:30+01:00".to_owned()),
    );
    root.insert(
        "updated_at_fractional".to_owned(),
        ClaimValue::String("2026-07-13T10:15:30.123Z".to_owned()),
    );

    assert!(validate_claim_payload(&registry, &ClaimValue::Object(root)).is_ok());
}

#[test]
fn json_claim_normalization_rejects_duplicates_and_confusables() {
    assert_eq!(
        claim_value_from_json_slice(br#"{"age":42,"age":43}"#),
        Err(ClaimsError::InvalidInput(
            ClaimsInvalidReason::DuplicateClaimName
        ))
    );

    assert_eq!(
        claim_value_from_json_slice("{\"nаme\":\"Alex\"}".as_bytes()),
        Err(ClaimsError::InvalidInput(
            ClaimsInvalidReason::ConfusableClaimName
        ))
    );
}

#[test]
fn claim_path_resolution_handles_missing_and_out_of_range_selectors() {
    let value = claim_value_from_json_slice(
        br#"{"address":{"street/name":"High Street"},"children":[{"name":"Sam"}]}"#,
    )
    .unwrap();

    let street = parse_claim_path("/claims/address/street~1name").unwrap();
    assert_eq!(
        resolve_claim_path(&value, &street).unwrap(),
        Some(&ClaimValue::String("High Street".to_owned()))
    );

    let child_name = parse_claim_path("/claims/children/0/name").unwrap();
    assert_eq!(
        value.resolve_path(&child_name).unwrap(),
        Some(&ClaimValue::String("Sam".to_owned()))
    );

    let age_over = claim_value_from_json_slice(br#"{"age_equal_or_over":{"18":true}}"#).unwrap();
    let age_over_path = parse_claim_path("/claims/age_equal_or_over/~218").unwrap();
    assert_eq!(
        age_over.resolve_path(&age_over_path).unwrap(),
        Some(&ClaimValue::Boolean(true))
    );

    let missing = parse_claim_path("/claims/address/postcode").unwrap();
    assert_eq!(resolve_claim_path(&value, &missing).unwrap(), None);

    let out_of_range = parse_claim_path("/claims/children/1/name").unwrap();
    assert_eq!(resolve_claim_path(&value, &out_of_range).unwrap(), None);
}

#[test]
fn path_entry_normalization_rejects_duplicate_and_conflicting_paths() {
    let duplicate_path = parse_claim_path("/claims/age").unwrap();
    assert_eq!(
        claim_value_from_path_entries([
            ClaimPathEntry {
                path: duplicate_path.clone(),
                value: ClaimValue::Unsigned(42),
            },
            ClaimPathEntry {
                path: duplicate_path,
                value: ClaimValue::Unsigned(43),
            },
        ]),
        Err(ClaimsError::InvalidInput(
            ClaimsInvalidReason::DuplicateClaimPath
        ))
    );

    assert_eq!(
        claim_value_from_path_entries([
            ClaimPathEntry {
                path: parse_claim_path("/claims/address").unwrap(),
                value: ClaimValue::String("not an object".to_owned()),
            },
            ClaimPathEntry {
                path: parse_claim_path("/claims/address/street").unwrap(),
                value: ClaimValue::String("High Street".to_owned()),
            },
        ]),
        Err(ClaimsError::InvalidInput(
            ClaimsInvalidReason::ParentChildClaimPathConflict
        ))
    );
}

#[test]
fn claim_payload_rejects_type_mismatches_unknowns_and_bad_dates() {
    let registry = nested_registry();

    let mut wrong_type = BTreeMap::new();
    wrong_type.insert("age".to_owned(), ClaimValue::String("42".to_owned()));
    assert_eq!(
        validate_claim_payload(&registry, &ClaimValue::Object(wrong_type)),
        Err(ClaimsError::InvalidInput(
            ClaimsInvalidReason::ClaimValueTypeMismatch
        ))
    );

    let mut unknown = BTreeMap::new();
    unknown.insert("unregistered".to_owned(), ClaimValue::Boolean(true));
    assert_eq!(
        validate_claim_payload(&registry, &ClaimValue::Object(unknown)),
        Err(ClaimsError::UnknownClaim)
    );

    let mut bad_date = BTreeMap::new();
    bad_date.insert(
        "birth_date".to_owned(),
        ClaimValue::String("2026-02-31".to_owned()),
    );
    assert_eq!(
        validate_claim_payload(&registry, &ClaimValue::Object(bad_date)),
        Err(ClaimsError::InvalidInput(ClaimsInvalidReason::InvalidDate))
    );
}

#[test]
fn claim_value_rejects_invalid_decimal_and_boundary_depth() {
    let definition = claim_definition("score", ClaimType::Decimal, true, Vec::new());
    assert_eq!(
        validate_claim_value(&definition, &ClaimValue::String("1e9".to_owned())),
        Err(ClaimsError::InvalidInput(
            ClaimsInvalidReason::ClaimValueTypeMismatch
        ))
    );
    assert_eq!(
        ClaimDecimal::new("1e9"),
        Err(ClaimsError::InvalidInput(
            ClaimsInvalidReason::InvalidDecimal
        ))
    );

    let mut value = ClaimValue::Null;
    for _ in 0..=MAX_CLAIM_VALUE_DEPTH {
        value = ClaimValue::Array(vec![value]);
    }
    let mut root = BTreeMap::new();
    root.insert("tags".to_owned(), value);

    assert_eq!(
        validate_claim_payload(&nested_registry(), &ClaimValue::Object(root)),
        Err(ClaimsError::InvalidInput(
            ClaimsInvalidReason::ClaimValueLimitExceeded
        ))
    );
}

#[test]
fn property_claim_paths_roundtrip_generated_segments() {
    let field_segments = [
        "alpha",
        "street/name",
        "tilde~field",
        "field.with.dot",
        "under_score",
        "hyphen-field",
    ];
    let index_segments = [0u32, 1, 42, 255];

    for first in field_segments {
        let first_encoded = reallyme_credential_claims::escape_field_segment(first);
        let path = claim_path(first_encoded.as_str()).unwrap();
        let parsed = parse_claim_path(path.as_str()).unwrap();
        assert_eq!(parsed.claim_id().as_deref(), Some(first_encoded.as_str()));

        for second in field_segments {
            let second_encoded = reallyme_credential_claims::escape_field_segment(second);
            let claim_id = format!("{first_encoded}/{second_encoded}");
            let path = claim_path(claim_id.as_str()).unwrap();
            let parsed = parse_claim_path(path.as_str()).unwrap();
            assert_eq!(parsed.claim_id().as_deref(), Some(claim_id.as_str()));
        }

        for index in index_segments {
            let claim_id = format!("{first_encoded}/{index}/alpha");
            let path = claim_path(claim_id.as_str()).unwrap();
            let parsed = parse_claim_path(path.as_str()).unwrap();
            assert_eq!(parsed.claim_id().as_deref(), Some(claim_id.as_str()));
        }
    }
}

#[test]
fn property_claim_paths_reject_generated_ambiguous_segments() {
    let oversized_segment = "a".repeat(MAX_CLAIM_PATH_SEGMENT_BYTES + 1);
    for claim_id in [
        "",
        "*",
        ".",
        "..",
        "0",
        "01",
        "123",
        "alpha/",
        "alpha//beta",
        "alpha/*",
        "alpha/01",
        "alpha/bad~2escape",
        "alpha/control\u{001f}",
        oversized_segment.as_str(),
    ] {
        assert_eq!(claim_path(claim_id), None);
    }

    let mut deep_claim_id = String::from("root");
    for _ in 0..MAX_CLAIM_PATH_DEPTH {
        deep_claim_id.push_str("/child");
    }
    assert_eq!(claim_path(deep_claim_id.as_str()), None);
}

#[test]
fn property_json_normalization_rejects_generated_duplicate_and_confusable_names() {
    for name in ["age", "address", "street_name", "field.with.dot"] {
        let payload = format!(r#"{{"{name}":1,"{name}":2}}"#);
        assert_eq!(
            claim_value_from_json_slice(payload.as_bytes()),
            Err(ClaimsError::InvalidInput(
                ClaimsInvalidReason::DuplicateClaimName
            ))
        );

        let nested = format!(r#"{{"holder":{{"{name}":1,"{name}":2}}}}"#);
        assert_eq!(
            claim_value_from_json_slice(nested.as_bytes()),
            Err(ClaimsError::InvalidInput(
                ClaimsInvalidReason::DuplicateClaimName
            ))
        );
    }

    for payload in [
        "{\"nаme\":\"Alex\"}",
        "{\"holder\":{\"аge\":42}}",
        "{\"emoji_😀\":true}",
    ] {
        assert_eq!(
            claim_value_from_json_slice(payload.as_bytes()),
            Err(ClaimsError::InvalidInput(
                ClaimsInvalidReason::ConfusableClaimName
            ))
        );
    }
}

#[test]
fn property_claim_dates_and_decimals_enforce_canonical_boundaries() {
    for value in ["0", "1", "-1", "0.1", "-0.1", "123456789.987654321"] {
        assert!(ClaimDecimal::new(value).is_ok());
    }

    for value in [
        "", "-", ".1", "1.", "01", "-0", "1.10", "1.0", "1e9", "NaN", "Infinity",
    ] {
        assert_eq!(
            ClaimDecimal::new(value),
            Err(ClaimsError::InvalidInput(
                ClaimsInvalidReason::InvalidDecimal
            ))
        );
    }

    for value in ["1904-02-29", "2000-02-29", "2026-07-13"] {
        assert!(ClaimDate::new(value).is_ok());
    }

    for value in ["1900-02-29", "2026-02-29", "2026-13-01", "2026-00-01"] {
        assert_eq!(
            ClaimDate::new(value),
            Err(ClaimsError::InvalidInput(ClaimsInvalidReason::InvalidDate))
        );
    }

    for value in [
        "2026-07-13T10:15:30Z",
        "2026-07-13T11:15:30+01:00",
        "2026-07-13T10:15:30.123Z",
    ] {
        assert!(ClaimDateTime::new(value).is_ok());
    }

    for value in [
        "2026-07-13",
        "2026-07-13T10:15:30",
        "2026-07-13T25:15:30Z",
        "2026-02-29T10:15:30Z",
    ] {
        assert_eq!(
            ClaimDateTime::new(value),
            Err(ClaimsError::InvalidInput(
                ClaimsInvalidReason::InvalidDateTime
            ))
        );
    }
}

#[test]
fn property_claim_dates_and_decimals_reject_invalid_boundaries() {
    for value in [
        "", "-", ".1", "1.", "01", "-0", "1.10", "1.0", "1e9", "NaN", "Infinity",
    ] {
        assert_eq!(
            ClaimDecimal::new(value),
            Err(ClaimsError::InvalidInput(
                ClaimsInvalidReason::InvalidDecimal
            ))
        );
    }

    for value in ["1900-02-29", "2026-02-29", "2026-13-01", "2026-00-01"] {
        assert_eq!(
            ClaimDate::new(value),
            Err(ClaimsError::InvalidInput(ClaimsInvalidReason::InvalidDate))
        );
    }

    for value in [
        "2026-07-13",
        "2026-07-13T10:15:30",
        "2026-07-13T25:15:30Z",
        "2026-02-29T10:15:30Z",
    ] {
        assert_eq!(
            ClaimDateTime::new(value),
            Err(ClaimsError::InvalidInput(
                ClaimsInvalidReason::InvalidDateTime
            ))
        );
    }
}
