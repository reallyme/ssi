// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Tests for generated DID protobuf bindings.

#![cfg(feature = "generated")]
#![allow(missing_docs)]
#![allow(clippy::unwrap_used)]

use buffa::{EnumValue, Enumeration, Message, MessageField};
use reallyme_ssi_proto::generated::proto::{
    identity::did::{me::v1::DidMeRecord, v1::VerificationMethodType},
    meid::did::v1::{
        domain_verification::Binding, DIDDocument, DomainVerification, WellKnownBinding,
    },
    reallyme::crypto::v1::KemAlgorithm,
};
use serde_json::json;
use zeroize::Zeroize;

#[test]
fn verification_method_type_enum_value_is_stable() {
    assert_eq!(
        VerificationMethodType::VERIFICATION_METHOD_TYPE_MULTIKEY.to_i32(),
        1
    );
}

#[test]
fn imported_crypto_kem_numbers_match_the_authoritative_sparse_contract() {
    assert_eq!(KemAlgorithm::KEM_ALGORITHM_ML_KEM_512.to_i32(), 1_000);
    assert_eq!(KemAlgorithm::KEM_ALGORITHM_ML_KEM_768.to_i32(), 1_010);
    assert_eq!(KemAlgorithm::KEM_ALGORITHM_ML_KEM_1024.to_i32(), 1_020);
    assert_eq!(KemAlgorithm::KEM_ALGORITHM_X_WING_768.to_i32(), 1_100);
    assert_eq!(
        KemAlgorithm::values(),
        &[
            KemAlgorithm::KEM_ALGORITHM_UNSPECIFIED,
            KemAlgorithm::KEM_ALGORITHM_ML_KEM_512,
            KemAlgorithm::KEM_ALGORITHM_ML_KEM_768,
            KemAlgorithm::KEM_ALGORITHM_ML_KEM_1024,
            KemAlgorithm::KEM_ALGORITHM_X_WING_768,
        ]
    );
}

#[test]
fn did_me_record_round_trips_with_buffa() {
    let spec_document = DIDDocument {
        sequence: 1,
        current_core: "bafyreibasestablecid".to_owned(),
        ..DIDDocument::default()
    };
    let record = DidMeRecord {
        spec_document: MessageField::some(spec_document),
        ..DidMeRecord::default()
    };

    let encoded = record.encode_to_vec();
    let decoded = DidMeRecord::decode(&mut encoded.as_slice()).unwrap();
    let decoded_spec_document = decoded.spec_document.as_option().unwrap();

    assert_eq!(decoded_spec_document.sequence, 1);
    assert_eq!(decoded_spec_document.current_core, "bafyreibasestablecid");
}

#[test]
fn enum_value_wrapper_accepts_multikey() {
    let value = EnumValue::from(VerificationMethodType::VERIFICATION_METHOD_TYPE_MULTIKEY);

    assert_eq!(value.to_i32(), 1);
}

#[test]
fn did_me_domain_verification_accepts_spec_wellknown_json_key() {
    let value = json!({
        "type": "HttpsWellKnownVerification",
        "domain": "example.com",
        "method": "wellknown",
        "wellknown": {
            "uri": "/.well-known/did-configuration.json",
            "content": "{}"
        }
    });

    let parsed: DomainVerification = serde_json::from_value(value).unwrap();

    assert_eq!(parsed.method, "wellknown");
    let binding = parsed.binding.unwrap();
    assert!(matches!(binding, Binding::WellKnown(_)));
    if let Binding::WellKnown(binding) = binding {
        assert_eq!(binding.uri, "/.well-known/did-configuration.json");
        assert_eq!(binding.content, "{}");
    }
}

#[test]
fn did_me_domain_verification_serializes_spec_wellknown_json_key() {
    let verification = DomainVerification {
        r#type: "HttpsWellKnownVerification".to_owned(),
        domain: "example.com".to_owned(),
        method: "wellknown".to_owned(),
        binding: Some(Binding::WellKnown(Box::new(WellKnownBinding {
            uri: "/.well-known/did-configuration.json".to_owned(),
            content: "{}".to_owned(),
            ..WellKnownBinding::default()
        }))),
        ..DomainVerification::default()
    };

    let serialized = serde_json::to_value(verification).unwrap();
    let object = serialized.as_object().unwrap();

    assert!(object.contains_key("wellknown"));
    assert!(!object.contains_key("wellKnown"));
    assert!(!object.contains_key("well_known"));
}

#[test]
fn did_me_document_package_cleanup_clears_identifying_and_proof_material() {
    let mut document = DIDDocument {
        id: "did:me:sensitive".to_owned(),
        context: vec!["https://example.invalid/private-context".to_owned()],
        current_core: "private-core-cid".to_owned(),
        core_cbor: vec![1, 2, 3, 4],
        attestations: vec![
            reallyme_ssi_proto::generated::proto::meid::did::v1::Attestation {
                vm: "#private-key".to_owned(),
                sig: vec![5, 6, 7],
                ..Default::default()
            },
        ],
        ..Default::default()
    };

    document.zeroize();

    assert!(document.id.is_empty());
    assert!(document.context.is_empty());
    assert!(document.current_core.is_empty());
    assert!(document.core_cbor.is_empty());
    assert!(document.attestations.is_empty());
}
