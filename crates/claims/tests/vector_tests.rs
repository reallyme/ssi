// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(missing_docs, clippy::unwrap_used)]
//! Test coverage for this crate.

use std::collections::BTreeMap;

use buffa::Message;
use reallyme_codec::base64url::base64url_to_bytes;
use reallyme_credential_claims::{
    claim_value_from_path_entries, escape_field_segment, parse_claim_path,
    profiles::{
        eu_address_v1, eu_age_v1, eu_company_v1, eu_diploma_v1, eu_driving_license_v1, eu_eaa_v1,
        eu_eidas_vid_v1, eu_health_v1, eu_passport_v1, eu_pid_v1, eu_professional_license_v1,
        eu_tax_v1, icao_passport_v1,
    },
    validate_claim_payload, ClaimDate, ClaimDateTime, ClaimDecimal, ClaimDefinition,
    ClaimDisclosurePolicy, ClaimPathEntry, ClaimType, ClaimValue, ClaimsRegistry,
    ENCODING_JCS_UTF8,
};
use reallyme_ssi_proto::generated::proto::identity::credential::v1 as credential_pb;
use reallyme_ssi_proto::generated::proto::identity::presentation::v1::{
    __buffa::oneof::claim_disclosure::Value as ProtoClaimDisclosureValue, ClaimDisclosure,
};
use serde_json::Value;

const CLAIMS_NORMALIZATION_VECTORS: &str =
    include_str!("../../../vectors/claims/normalization.json");
const CLAIMS_PREDEFINED_CREDENTIAL_VECTORS: &str =
    include_str!("../../../vectors/claims/predefined-credentials.json");
const CLAIMS_CATALOG_SOURCES: &str = include_str!("../../../vectors/claims/catalog-sources.json");
const CLAIMS_VECTOR_MANIFEST: &str = include_str!("../../../vectors/manifest.json");
const CLAIMS_NAMESPACE: &str = "org.iso.18013.5.1";
const APPROVED_CLAIMS_VECTOR_SOURCES: &[&str] = &[
    "ReallyMe claim normalization model",
    "EU-2024-2977",
    "EU-2024-1183",
    "EU-2025-1569",
    "ISO18013-5",
    "ICAO9303",
    "ELM-3",
    "EU-2003-751",
    "EUDI-ARF",
];

#[test]
fn conformance_vectors_normalize_claims_across_formats() {
    let suite: Value = serde_json::from_str(CLAIMS_NORMALIZATION_VECTORS).unwrap();
    let registry = registry_from_vector(&suite["registry"]);
    let expected = canonical_claims_from_vector(&suite["canonical_claims"]);

    for case in suite["cases"].as_array().unwrap() {
        let normalized = extract_case_claims(case, &registry);

        assert_eq!(normalized, expected, "case id {}", case["id"]);
        validate_claim_payload(&registry, &normalized).unwrap();
    }
}

#[test]
fn predefined_credential_vectors_normalize_across_formats() {
    let suite: Value = serde_json::from_str(CLAIMS_PREDEFINED_CREDENTIAL_VECTORS).unwrap();
    let formats = suite["formats"].as_array().unwrap();

    for profile in suite["profiles"].as_array().unwrap() {
        let claimset_id = profile["claimset_id"].as_str().unwrap();
        let registry = predefined_registry_for_claimset(claimset_id);
        let expected = canonical_claims_from_vector(&profile["canonical_claims"]);

        for format in formats {
            let format = format.as_str().unwrap();
            let normalized = extract_predefined_profile_claims(format, profile, &registry);

            assert_eq!(
                normalized, expected,
                "claimset {claimset_id} format {format}"
            );
            validate_claim_payload(&registry, &normalized).unwrap();
        }
    }
}

#[test]
fn claims_vector_sources_are_internal_or_official() {
    let manifest: Value = serde_json::from_str(CLAIMS_VECTOR_MANIFEST).unwrap();
    for suite in manifest["suites"].as_array().unwrap() {
        let path = suite["path"].as_str().unwrap();
        if path.starts_with("claims/") {
            assert_approved_claims_vector_source(suite["source"].as_str().unwrap());
        }
    }

    let predefined: Value = serde_json::from_str(CLAIMS_PREDEFINED_CREDENTIAL_VECTORS).unwrap();
    for profile in predefined["profiles"].as_array().unwrap() {
        assert_approved_claims_vector_source(profile["source"].as_str().unwrap());
    }

    let catalog_sources: Value = serde_json::from_str(CLAIMS_CATALOG_SOURCES).unwrap();
    assert_approved_claims_vector_source(
        catalog_sources["official_sector_catalog_assessment"]["source"]
            .as_str()
            .unwrap(),
    );
    for profile in catalog_sources["profiles"].as_array().unwrap() {
        assert_approved_claims_vector_source(profile["source"].as_str().unwrap());
    }
}

fn assert_approved_claims_vector_source(source: &str) {
    for source_id in source.split(',').map(str::trim) {
        assert!(
            APPROVED_CLAIMS_VECTOR_SOURCES.contains(&source_id),
            "claims vector source {source_id} is not approved",
        );
    }
}

fn predefined_registry_for_claimset(claimset_id: &str) -> ClaimsRegistry {
    match claimset_id {
        "eu.pid.v1" => eu_pid_v1(),
        "eu.age.v1" => eu_age_v1(),
        "eu.address.v1" => eu_address_v1(),
        "eu.eaa.v1" => eu_eaa_v1(),
        "eu.company.v1" => eu_company_v1(),
        "eu.tax.v1" => eu_tax_v1(),
        "eu.passport.v1" => eu_passport_v1(),
        "icao.passport.v1" => icao_passport_v1(),
        "eu.driving_license.v1" => eu_driving_license_v1(),
        "eu.diploma.v1" => eu_diploma_v1(),
        "eu.health.v1" => eu_health_v1(),
        "eu.professional_license.v1" => eu_professional_license_v1(),
        "eu.eidas-vid.v1" => eu_eidas_vid_v1(),
        _ => ClaimsRegistry {
            claimset_id: claimset_id.to_owned(),
            claims: BTreeMap::new(),
        },
    }
}

fn extract_predefined_profile_claims(
    format: &str,
    profile: &Value,
    registry: &ClaimsRegistry,
) -> ClaimValue {
    match format {
        "ietf-sd-jwt-vc" | "jwt-vc" | "w3c-vc" => {
            normalize_json_payload(&profile["payload"], registry)
        }
        "mdoc" => normalize_json_payload(&profile["payload"], registry),
        "presentation-proto" => extract_presentation_proto_claims(
            &generated_disclosures_from_vector(&proto_payload_from_profile(profile)),
        ),
        "credential-proto" => extract_credential_proto_claims(
            &generated_private_bundle_from_vector(&proto_payload_from_profile(profile)),
        ),
        _ => ClaimValue::Null,
    }
}

fn proto_payload_from_profile(profile: &Value) -> Value {
    let mut payload = serde_json::Map::new();
    payload.insert("claims".to_owned(), profile["canonical_claims"].clone());
    Value::Object(payload)
}

fn registry_from_vector(value: &Value) -> ClaimsRegistry {
    let claimset_id = value["claimset_id"].as_str().unwrap().to_owned();
    let mut claims = BTreeMap::new();
    for (claim_id, definition) in value["claims"].as_object().unwrap() {
        let claim_type = claim_type_from_vector(definition["type"].as_str().unwrap());
        claims.insert(
            claim_id.clone(),
            ClaimDefinition {
                claim_id: claim_id.clone(),
                claim_type,
                encoding: ENCODING_JCS_UTF8.to_owned(),
                disclosure: ClaimDisclosurePolicy {
                    allow_reveal: true,
                    predicates: Vec::new(),
                },
            },
        );
    }

    ClaimsRegistry {
        claimset_id,
        claims,
    }
}

fn claim_type_from_vector(value: &str) -> ClaimType {
    match value {
        "String" => ClaimType::String,
        "Boolean" => ClaimType::Boolean,
        "SignedInteger" => ClaimType::SignedInteger,
        "UnsignedInteger" => ClaimType::UnsignedInteger,
        "Decimal" => ClaimType::Decimal,
        "Bytes" => ClaimType::Bytes,
        "Date" => ClaimType::Date,
        "DateTime" => ClaimType::DateTime,
        "Null" => ClaimType::Null,
        "Object" => ClaimType::Object,
        "Array" => ClaimType::Array,
        _ => ClaimType::Unspecified,
    }
}

fn canonical_claims_from_vector(value: &Value) -> ClaimValue {
    let entries = value
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| ClaimPathEntry {
            path: parse_claim_path(entry["path"].as_str().unwrap()).unwrap(),
            value: typed_value_from_vector(&entry["value"]),
        })
        .collect::<Vec<_>>();
    claim_value_from_path_entries(entries).unwrap()
}

fn extract_case_claims(case: &Value, registry: &ClaimsRegistry) -> ClaimValue {
    match case["format"].as_str().unwrap() {
        "ietf-sd-jwt-vc" => {
            normalize_json_payload(&case["payload"]["verified_claims"]["claims"], registry)
        }
        "mdoc" => {
            normalize_json_payload(&case["payload"]["namespaces"][CLAIMS_NAMESPACE], registry)
        }
        "jwt-vc" => normalize_json_payload(&case["payload"]["vc"]["credentialSubject"], registry),
        "w3c-vc" => normalize_json_payload(&case["payload"]["credentialSubject"], registry),
        "presentation-proto" => {
            extract_presentation_proto_claims(&generated_disclosures_from_vector(&case["payload"]))
        }
        "credential-proto" => {
            extract_credential_proto_claims(&generated_private_bundle_from_vector(&case["payload"]))
        }
        _ => ClaimValue::Null,
    }
}

fn normalize_json_payload(payload: &Value, registry: &ClaimsRegistry) -> ClaimValue {
    let mut entries = Vec::new();
    collect_json_entries(payload, registry, &mut Vec::new(), &mut entries);
    claim_value_from_path_entries(entries).unwrap()
}

fn collect_json_entries(
    value: &Value,
    registry: &ClaimsRegistry,
    path_segments: &mut Vec<String>,
    entries: &mut Vec<ClaimPathEntry>,
) {
    let path = path_from_segments(path_segments);
    if let Some(definition) = registry.claims.get(path.trim_start_matches("/claims/")) {
        entries.push(ClaimPathEntry {
            path: parse_claim_path(path.as_str()).unwrap(),
            value: json_value_for_definition(definition, value),
        });
        return;
    }

    match value {
        Value::Object(object) => {
            for (key, child) in object {
                path_segments.push(escape_field_segment(key.as_str()));
                collect_json_entries(child, registry, path_segments, entries);
                path_segments.pop();
            }
        }
        Value::Array(array) => {
            for (index, child) in array.iter().enumerate() {
                path_segments.push(index.to_string());
                collect_json_entries(child, registry, path_segments, entries);
                path_segments.pop();
            }
        }
        _ => {
            let parsed = parse_claim_path(path.as_str()).unwrap();
            let claim_id = parsed.claim_id().unwrap();
            let definition = registry.claims.get(claim_id.as_str()).unwrap();
            entries.push(ClaimPathEntry {
                path: parsed,
                value: json_value_for_definition(definition, value),
            });
        }
    }
}

fn path_from_segments(segments: &[String]) -> String {
    if segments.is_empty() {
        return "/claims".to_owned();
    }
    let mut out = "/claims/".to_owned();
    out.push_str(segments.join("/").as_str());
    out
}

fn json_value_for_definition(definition: &ClaimDefinition, value: &Value) -> ClaimValue {
    match definition.claim_type {
        ClaimType::String => ClaimValue::String(value.as_str().unwrap().to_owned()),
        ClaimType::Boolean => ClaimValue::Boolean(value.as_bool().unwrap()),
        ClaimType::Integer | ClaimType::SignedInteger => {
            ClaimValue::Signed(value.as_i64().unwrap())
        }
        ClaimType::UnsignedInteger => ClaimValue::Unsigned(value.as_u64().unwrap()),
        ClaimType::Number | ClaimType::Decimal => {
            let lexical = value
                .as_str()
                .map(str::to_owned)
                .unwrap_or_else(|| value.as_number().unwrap().to_string());
            ClaimValue::Decimal(ClaimDecimal::new(lexical).unwrap())
        }
        ClaimType::Bytes => ClaimValue::Bytes(base64url_to_bytes(value.as_str().unwrap()).unwrap()),
        ClaimType::Date => ClaimValue::Date(ClaimDate::new(value.as_str().unwrap()).unwrap()),
        ClaimType::DateTime => {
            ClaimValue::DateTime(ClaimDateTime::new(value.as_str().unwrap()).unwrap())
        }
        ClaimType::Null => {
            assert!(value.is_null());
            ClaimValue::Null
        }
        ClaimType::Object | ClaimType::Array | ClaimType::Unspecified => {
            ClaimValue::from_json(value).unwrap()
        }
    }
}

fn generated_disclosures_from_vector(payload: &Value) -> Vec<ClaimDisclosure> {
    payload["claims"]
        .as_array()
        .unwrap()
        .iter()
        .map(|claim| {
            let disclosure = ClaimDisclosure {
                claim_path: claim["path"].as_str().unwrap().to_owned(),
                value: Some(ProtoClaimDisclosureValue::RevealedValue(
                    serde_json::to_vec(&claim["value"]).unwrap(),
                )),
                ..ClaimDisclosure::default()
            };
            let encoded = disclosure.encode_to_vec();
            ClaimDisclosure::decode(&mut encoded.as_slice()).unwrap()
        })
        .collect()
}

fn extract_presentation_proto_claims(disclosures: &[ClaimDisclosure]) -> ClaimValue {
    let mut entries = Vec::with_capacity(disclosures.len());
    for disclosure in disclosures {
        let path = parse_claim_path(disclosure.claim_path.as_str()).unwrap();
        let value = match &disclosure.value {
            Some(ProtoClaimDisclosureValue::RevealedValue(bytes)) => {
                let oneof_value: Value = serde_json::from_slice(bytes).unwrap();
                typed_value_from_vector(&oneof_value)
            }
            Some(
                ProtoClaimDisclosureValue::Threshold(_)
                | ProtoClaimDisclosureValue::Range(_)
                | ProtoClaimDisclosureValue::Set(_),
            )
            | None => ClaimValue::Null,
        };
        entries.push(ClaimPathEntry { path, value });
    }
    claim_value_from_path_entries(entries).unwrap()
}

fn generated_private_bundle_from_vector(payload: &Value) -> credential_pb::SubjectPrivateBundle {
    let bundle = credential_pb::SubjectPrivateBundle {
        claims: payload["claims"]
            .as_array()
            .unwrap()
            .iter()
            .enumerate()
            .map(|(index, claim)| credential_pb::ClaimOpening {
                claim_path: claim["path"].as_str().unwrap().to_owned(),
                value: serde_json::to_vec(&claim["value"]).unwrap(),
                index: u32::try_from(index).unwrap(),
                ..credential_pb::ClaimOpening::default()
            })
            .collect(),
        ..credential_pb::SubjectPrivateBundle::default()
    };
    let encoded = bundle.encode_to_vec();
    credential_pb::SubjectPrivateBundle::decode(&mut encoded.as_slice()).unwrap()
}

fn extract_credential_proto_claims(bundle: &credential_pb::SubjectPrivateBundle) -> ClaimValue {
    let mut entries = Vec::with_capacity(bundle.claims.len());
    for opening in &bundle.claims {
        let path = parse_claim_path(opening.claim_path.as_str()).unwrap();
        let oneof_value: Value = serde_json::from_slice(opening.value.as_slice()).unwrap();
        entries.push(ClaimPathEntry {
            path,
            value: typed_value_from_vector(&oneof_value),
        });
    }
    claim_value_from_path_entries(entries).unwrap()
}

fn typed_value_from_vector(value: &Value) -> ClaimValue {
    if let Some(value) = value.get("string").and_then(Value::as_str) {
        return ClaimValue::String(value.to_owned());
    }
    if let Some(value) = value.get("date").and_then(Value::as_str) {
        return ClaimValue::Date(ClaimDate::new(value).unwrap());
    }
    if let Some(value) = value.get("date_time").and_then(Value::as_str) {
        return ClaimValue::DateTime(ClaimDateTime::new(value).unwrap());
    }
    if let Some(value) = value.get("decimal").and_then(Value::as_str) {
        return ClaimValue::Decimal(ClaimDecimal::new(value).unwrap());
    }
    if let Some(value) = value.get("bytes_b64").and_then(Value::as_str) {
        return ClaimValue::Bytes(base64url_to_bytes(value).unwrap());
    }
    if let Some(value) = value.get("boolean").and_then(Value::as_bool) {
        return ClaimValue::Boolean(value);
    }
    if let Some(value) = value.get("unsigned").and_then(Value::as_u64) {
        return ClaimValue::Unsigned(value);
    }
    if let Some(value) = value.get("signed").and_then(Value::as_i64) {
        return ClaimValue::Signed(value);
    }
    if value.get("null").and_then(Value::as_bool) == Some(true) {
        return ClaimValue::Null;
    }
    if let Some(value) = value.get("json") {
        return ClaimValue::from_json(value).unwrap();
    }
    ClaimValue::Null
}
