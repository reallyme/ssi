// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Test coverage for this crate.
#![allow(missing_docs)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::panic)]
#![allow(clippy::expect_used)]

use buffa_types::google::protobuf::{value::Kind, Value};
use reallyme_codec::base64url::{base64url_to_bytes, bytes_to_base64url};
use reallyme_codec::cbor::{encode_dag_cbor, CborValue};
use reallyme_did_types::{Controller, DIDDocument, Service, UpdatePolicy};
use reallyme_ssi_proto::generated::proto::meid::did::v1::DIDDocument as PbDIDDocument;
use reallyme_ssi_proto_codec::did::{
    decode_proto, encode_proto, json_to_proto, proto_to_json, DidProtoCodecError,
};

// DID documents erase their owned identity data on drop. Rust therefore disallows
// struct-update syntax; this test-only constructor keeps fixtures readable without
// bypassing the production destructor.
macro_rules! did_document {
    ($($field:ident: $value:expr),+ $(,)?) => {{
        let mut document = DIDDocument::default();
        $(document.$field = $value;)+
        document
    }};
}

/// Minimal update policy helper
fn minimal_policy() -> UpdatePolicy {
    UpdatePolicy {
        allowed_verification_methods: vec!["#ed25519".into()],
        threshold: None,
    }
}

fn controller_value(controller: &str) -> Option<Value> {
    Some(Value {
        kind: Some(Kind::StringValue(controller.to_string())),
        ..Value::default()
    })
}

//
// -----------------------------------------------------------------------------
// Proto3 default ↔ JSON absence invariants
// -----------------------------------------------------------------------------

#[test]
fn proto_defaults_become_json_none() {
    let proto = PbDIDDocument {
        id: "did:me:123".into(),
        controller: controller_value("did:me:123").into(),
        ..Default::default()
    };

    let json = proto_to_json(&proto).unwrap();

    assert!(json.hardware_bound.is_none());
    assert!(json.biometric_protected.is_none());
    assert!(json.device_model.is_none());
    assert!(json.user_verification_method.is_none());
}

#[test]
fn false_bool_is_preserved() {
    let doc = did_document! {
        id: "did:me:123".into(),
        controller: Controller::Single("did:me:123".into()),
        hardware_bound: Some(false),
        core_cbor: bytes_to_base64url(&[0x01]), // valid
        current_core: "cid123".into(),
        update_policy: Some(minimal_policy()),
    };

    let back = proto_to_json(&json_to_proto(&doc).unwrap()).unwrap();

    assert_eq!(back.hardware_bound, Some(false));
}

//
// -----------------------------------------------------------------------------
// Forward-compatibility invariants
// -----------------------------------------------------------------------------

#[test]
fn unknown_user_verification_string_is_preserved() {
    let proto = PbDIDDocument {
        id: "did:me:123".into(),
        controller: controller_value("did:me:123").into(),
        user_verification_method: "future-method".into(),
        ..Default::default()
    };

    let json = proto_to_json(&proto).unwrap();
    assert_eq!(
        json.user_verification_method.as_deref(),
        Some("future-method")
    );
}

//
// -----------------------------------------------------------------------------
// Canonical binary integrity invariants
// -----------------------------------------------------------------------------

#[test]
fn core_cbor_is_bit_exact_roundtrip() {
    // Construct a minimal canonical DID core object
    let cbor = CborValue::Map(vec![
        ("id".to_string(), CborValue::String("did:me:123".into())),
        ("sequence".to_string(), CborValue::Int(1)),
    ]);

    let cbor_bytes = encode_dag_cbor(&cbor).unwrap();

    let doc = did_document! {
        id: "did:me:123".into(),
        controller: Controller::Single("did:me:123".into()),
        core_cbor: bytes_to_base64url(&cbor_bytes),
        current_core: "cid123".into(),
        update_policy: Some(minimal_policy()),
    };

    let back = proto_to_json(&json_to_proto(&doc).unwrap()).unwrap();

    let out = base64url_to_bytes(&back.core_cbor).unwrap();
    assert_eq!(out, cbor_bytes);
}

#[test]
fn service_endpoint_json_is_preserved() {
    let doc = did_document! {
        id: "did:me:123".into(),
        controller: Controller::Single("did:me:123".into()),
        core_cbor: bytes_to_base64url(&[0x01]),
        current_core: "cid123".into(),
        update_policy: Some(minimal_policy()),
        service: vec![Service {
            id: "#svc".into(),
            service_type: "LinkedDomains".into(),
            service_endpoint: serde_json::json!({
                "origins": ["https://example.com"]
            }),
        }],
    };

    let back = proto_to_json(&json_to_proto(&doc).unwrap()).unwrap();

    assert_eq!(
        back.service[0].service_endpoint,
        doc.service[0].service_endpoint
    );
}

#[test]
fn minimal_proto_document_decodes() {
    let proto = PbDIDDocument {
        id: "did:me:min".into(),
        controller: controller_value("did:me:min").into(),
        ..Default::default()
    };

    let json = proto_to_json(&proto).unwrap();

    assert_eq!(json.id, "did:me:min");
    assert_eq!(json.controller, Controller::Single("did:me:min".into()));
}

#[test]
fn json_to_proto_is_deterministic() {
    let doc = did_document! {
        id: "did:me:123".into(),
        controller: Controller::Single("did:me:123".into()),
        core_cbor: "AAEC".into(),
        current_core: "cid123".into(),
        update_policy: Some(UpdatePolicy {
            allowed_verification_methods: vec!["#ed25519".into()],
            threshold: None,
        }),
    };

    let a = json_to_proto(&doc).unwrap();
    let b = json_to_proto(&doc).unwrap();

    assert_eq!(a, b);
}

#[test]
fn did_proto_rejects_truncated_buffa_message() {
    let proto = PbDIDDocument {
        id: "did:me:truncated".into(),
        controller: controller_value("did:me:truncated").into(),
        ..Default::default()
    };
    let mut encoded = encode_proto(&proto).unwrap();
    encoded.truncate(encoded.len().saturating_sub(1));

    assert_eq!(
        decode_proto(encoded.as_slice()).unwrap_err(),
        DidProtoCodecError::DecodeFailed
    );
}
