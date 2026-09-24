// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Tests for generated EUDI catalogue protobuf bindings.

#![cfg(feature = "generated")]
#![allow(missing_docs)]

use buffa::{EnumValue, Enumeration, Message};
use reallyme_ssi_proto::generated::proto::identity::eudi::v1::{
    EudiCatalogueDocument, EudiCatalogueKind, EudiCatalogueValidation,
};

#[test]
fn eudi_catalogue_messages_round_trip_with_buffa() {
    let document = EudiCatalogueDocument {
        kind: EnumValue::from(EudiCatalogueKind::Attribute),
        json: br#"{"identifier":"https://example.eu/attribute/1"}"#.to_vec(),
        ..EudiCatalogueDocument::default()
    };
    let validation = EudiCatalogueValidation {
        kind: EnumValue::from(EudiCatalogueKind::Attribute),
        localized_name_count: 1,
        distribution_count: 2,
        authentic_source_count: 1,
        semantic_review_required: false,
        ..EudiCatalogueValidation::default()
    };

    let document_bytes = document.encode_to_vec();
    let validation_bytes = validation.encode_to_vec();
    let decoded_document_result = EudiCatalogueDocument::decode(&mut document_bytes.as_slice());
    let decoded_validation_result =
        EudiCatalogueValidation::decode(&mut validation_bytes.as_slice());
    assert!(decoded_document_result.is_ok());
    assert!(decoded_validation_result.is_ok());
    let decoded_document = match decoded_document_result {
        Ok(value) => value,
        Err(_) => return,
    };
    let decoded_validation = match decoded_validation_result {
        Ok(value) => value,
        Err(_) => return,
    };

    assert_eq!(decoded_document, document);
    assert_eq!(decoded_validation, validation);
}

#[test]
fn eudi_catalogue_kind_values_are_stable_and_unknown_values_remain_detectable() {
    assert_eq!(EudiCatalogueKind::Attribute.to_i32(), 1);
    assert_eq!(EudiCatalogueKind::Attestation.to_i32(), 2);

    let unknown = EnumValue::<EudiCatalogueKind>::from(65_535);
    assert_eq!(unknown.to_i32(), 65_535);
    assert!(EudiCatalogueKind::from_i32(unknown.to_i32()).is_none());
}

#[test]
fn eudi_catalogue_document_rejects_truncated_buffa_message() {
    let malformed = [
        0x12, 0x02, // Field 2 declares two JSON bytes.
        b'{', // The second byte is absent.
    ];

    assert!(EudiCatalogueDocument::decode(&mut malformed.as_slice()).is_err());
}

#[test]
fn eudi_catalogue_document_debug_redacts_json() {
    const SENSITIVE_JSON: &[u8] = br#"{"subject":"sensitive-value"}"#;
    let document = EudiCatalogueDocument {
        kind: EnumValue::from(EudiCatalogueKind::Attribute),
        json: SENSITIVE_JSON.to_vec(),
        ..EudiCatalogueDocument::default()
    };

    let debug_output = format!("{document:?}");
    assert!(debug_output.contains("[REDACTED]"));
    assert!(!debug_output.contains("sensitive-value"));
}
