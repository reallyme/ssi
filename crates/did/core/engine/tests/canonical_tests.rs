// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Test coverage for this crate.
#![allow(missing_docs)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::panic)]
#![allow(clippy::expect_used)]

use identity_core_primitives::Algorithm;
use reallyme_codec::cbor::CborValue;
use reallyme_did_core::canonical::{cbor_to_json_value, json_to_cbor_value, normalize_json_value};
use reallyme_did_core::{
    Canonical, CanonicalService, CoreVerificationMethod, DidCore, UpdatePolicy,
};

#[test]
fn canonical_cbor_is_deterministic() {
    let a = sample_core();
    let b = sample_core();

    assert_eq!(a.canonical_cbor().unwrap(), b.canonical_cbor().unwrap());
}

#[test]
fn canonical_cbor_is_non_empty() {
    let core = sample_core();
    let bytes = core.canonical_cbor().unwrap();

    assert!(!bytes.is_empty());
}

#[test]
fn canonical_cbor_rejects_values_outside_cbor_int_range() {
    let mut core = sample_core();

    core.sequence = u64::MAX;
    assert!(core.canonical_cbor().is_err());

    core.sequence = 1;
    core.update_policy.threshold = Some(u64::MAX);
    assert!(core.canonical_cbor().is_err());
}

#[test]
fn cbor_byte_strings_are_not_projected_as_ambiguous_json_arrays() {
    assert!(cbor_to_json_value(&CborValue::Bytes(vec![1, 2, 3])).is_err());
    assert!(cbor_to_json_value(&CborValue::Array(vec![
        CborValue::Int(1),
        CborValue::Int(2),
        CborValue::Int(3),
    ]))
    .is_ok());
}

#[test]
fn canonical_json_keys_are_sorted_with_insertion_ordered_maps() {
    let mut input = serde_json::Map::new();
    input.insert("z".to_owned(), serde_json::json!(1));
    input.insert("a".to_owned(), serde_json::json!(2));
    let normalized = normalize_json_value(&serde_json::Value::Object(input));
    let keys = normalized
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect::<Vec<_>>();
    assert_eq!(keys, ["a", "z"]);

    let cbor = json_to_cbor_value(&normalized).unwrap();
    let entries = match cbor {
        CborValue::Map(entries) => entries,
        _ => panic!("normalized object must project to a CBOR map"),
    };
    assert_eq!(entries[0].0, "a");
    assert_eq!(entries[1].0, "z");
}

fn sample_core() -> DidCore {
    DidCore {
        id: "did:me:test".into(),
        sequence: 1,
        nonce: Some(vec![0; 16]),
        controller: vec!["did:me:test".into()],
        controller_keys: vec![CoreVerificationMethod {
            id: "#ed25519".into(),
            vm_type: "Multikey".into(),
            algorithm: Algorithm::Ed25519,
            public_key_multibase: "zDummyKey".into(),
        }],
        authentication: vec!["#ed25519".into()],
        assertion: vec!["#ed25519".into()],
        key_agreement: vec![],
        services: vec![CanonicalService {
            id: "#svc".into(),
            service_type: "Messaging".into(),
            service_endpoint: CborValue::Map(vec![(
                "uri".into(),
                CborValue::String("https://example.com".into()),
            )]),
        }],
        update_policy: UpdatePolicy {
            allowed_verification_methods: vec!["#ed25519".into()],
            threshold: None,
        },
        prev: Some("bafyPrevCid".into()),
    }
}
