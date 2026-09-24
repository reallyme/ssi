// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(missing_docs, clippy::unwrap_used)]
//! Test coverage for SDK-facing claims commands.

use std::collections::BTreeMap;

use reallyme_credential_claims::{
    classify_claim_sensitivity, compare_claims_json, localize_claims, map_claims_json,
    normalize_claims_json_slice, redact_claims_json, validate_claims_json_slice,
    validate_claims_registry, ClaimDefinition, ClaimDisclosurePolicy, ClaimMapping,
    ClaimSensitivity, ClaimType, ClaimsCommandOutcome, ClaimsError, ClaimsInvalidReason,
    ClaimsRegistry, DisclosureMode, ENCODING_JCS_UTF8,
};
use serde_json::json;
use zeroize::Zeroize;

fn definition(claim_id: &str, claim_type: ClaimType) -> ClaimDefinition {
    ClaimDefinition {
        claim_id: claim_id.to_owned(),
        claim_type,
        encoding: ENCODING_JCS_UTF8.to_owned(),
        disclosure: ClaimDisclosurePolicy {
            allow_reveal: true,
            predicates: vec![DisclosureMode::Eq],
        },
    }
}

fn registry() -> ClaimsRegistry {
    let mut claims = BTreeMap::new();
    claims.insert(
        "given_name".to_owned(),
        definition("given_name", ClaimType::String),
    );
    claims.insert(
        "birth_date".to_owned(),
        definition("birth_date", ClaimType::Date),
    );
    ClaimsRegistry {
        claimset_id: "commands.claims.v1".to_owned(),
        claims,
    }
}

#[test]
fn claims_commands_validate_and_detect_malicious_json() {
    let registry = registry();

    let registry_result = validate_claims_registry(&registry);
    assert!(registry_result.valid);
    assert_eq!(registry_result.outcome, ClaimsCommandOutcome::Valid);

    let duplicate_result =
        validate_claims_json_slice(&registry, br#"{"given_name":"Ada","given_name":"Eve"}"#);
    assert!(!duplicate_result.valid);
    assert_eq!(
        duplicate_result.errors[0].error,
        ClaimsError::InvalidInput(ClaimsInvalidReason::DuplicateClaimName)
    );
}

#[test]
fn claims_commands_normalize_map_compare_and_redact() {
    let source = json!({
        "given_name": "Ada",
        "birth_date": "1815-12-10"
    });

    let normalized =
        normalize_claims_json_slice(br#"{"birth_date":"1815-12-10","given_name":"Ada"}"#).unwrap();
    assert!(compare_claims_json(&source, &normalized.normalized).unwrap());

    let mapped = map_claims_json(
        &source,
        &[ClaimMapping {
            source_path: "/claims/given_name".to_owned(),
            target_path: "/claims/name/display".to_owned(),
        }],
    )
    .unwrap();
    assert_eq!(mapped.claims.pointer("/name/display"), Some(&json!("Ada")));

    let redacted = redact_claims_json(&source, &["/claims/birth_date".to_owned()]).unwrap();
    assert_eq!(redacted.claims.pointer("/birth_date"), Some(&json!(null)));
}

#[test]
fn claims_commands_classify_and_localize_from_registry() {
    let registry = registry();

    let sensitivity = classify_claim_sensitivity(&registry);
    assert_eq!(sensitivity.claims[0].claim_id, "birth_date");
    assert_eq!(
        sensitivity.claims[0].sensitivity,
        ClaimSensitivity::Sensitive
    );

    let localized = localize_claims(&registry, "en-US");
    assert_eq!(localized.claims[0].locale, "en-US");
    assert_eq!(localized.claims[0].label, "Birth Date");
}

#[test]
fn claim_payload_and_registry_owners_redact_and_zeroize() {
    let mut normalized = normalize_claims_json_slice(br#"{"given_name":"Ada"}"#).unwrap();
    let diagnostic = format!("{normalized:?}");
    assert!(!diagnostic.contains("Ada"));
    assert!(diagnostic.contains("<redacted>"));

    normalized.zeroize();
    assert_eq!(normalized.normalized, json!({}));

    let mut registry = registry();
    let diagnostic = format!("{registry:?}");
    assert!(!diagnostic.contains("given_name"));
    assert!(diagnostic.contains("<redacted>"));

    registry.zeroize();
    assert!(registry.claimset_id.is_empty());
    assert!(registry.claims.is_empty());
}
