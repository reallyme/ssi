// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Tests for generated common protobuf bindings.

#![cfg(feature = "generated")]
#![allow(missing_docs)]

use buffa::{EnumValue, Enumeration, Message};
use reallyme_ssi_proto::generated::proto::reallyme::identity::common::v1::{
    IdentityStackError, IdentityStackErrorDomain,
};
use serde_json::json;

#[test]
fn identity_stack_error_domain_codes_are_stable() {
    assert_eq!(
        IdentityStackErrorDomain::IDENTITY_STACK_ERROR_DOMAIN_IDENTITY_CORE.to_i32(),
        4
    );
    assert_eq!(
        IdentityStackErrorDomain::IDENTITY_STACK_ERROR_DOMAIN_ZK.to_i32(),
        9
    );
    assert_eq!(
        IdentityStackErrorDomain::IDENTITY_STACK_ERROR_DOMAIN_CODEC.to_i32(),
        10
    );
}

#[test]
fn identity_stack_error_proto_round_trips_with_buffa() {
    let error = IdentityStackError {
        domain: EnumValue::from(
            IdentityStackErrorDomain::IDENTITY_STACK_ERROR_DOMAIN_IDENTITY_CORE,
        ),
        reason_code: 1,
        correlation_id: "corr_01".to_owned(),
        ..IdentityStackError::default()
    };

    let encoded = error.encode_to_vec();
    let decoded_result = IdentityStackError::decode(&mut encoded.as_slice());
    assert!(decoded_result.is_ok());
    let decoded = match decoded_result {
        Ok(decoded) => decoded,
        Err(_) => return,
    };

    assert_eq!(
        decoded.domain.to_i32(),
        IdentityStackErrorDomain::IDENTITY_STACK_ERROR_DOMAIN_IDENTITY_CORE.to_i32()
    );
    assert_eq!(decoded.reason_code, 1);
    assert_eq!(decoded.correlation_id, "corr_01");
}

#[test]
fn identity_stack_error_can_preserve_lower_layer_origin_domain() {
    let error = IdentityStackError {
        domain: EnumValue::from(IdentityStackErrorDomain::IDENTITY_STACK_ERROR_DOMAIN_JOSE),
        reason_code: 122,
        correlation_id: "corr_jose_01".to_owned(),
        ..IdentityStackError::default()
    };

    let encoded = error.encode_to_vec();
    let decoded_result = IdentityStackError::decode(&mut encoded.as_slice());
    assert!(decoded_result.is_ok());
    let decoded = match decoded_result {
        Ok(decoded) => decoded,
        Err(_) => return,
    };

    assert_eq!(
        decoded.domain.to_i32(),
        IdentityStackErrorDomain::IDENTITY_STACK_ERROR_DOMAIN_JOSE.to_i32()
    );
    assert_eq!(decoded.reason_code, 122);
    assert_eq!(decoded.correlation_id, "corr_jose_01");
}

#[test]
fn identity_stack_error_preserves_unknown_domain_code_for_fail_closed_mapping() {
    let error = IdentityStackError {
        domain: EnumValue::from(99),
        reason_code: 7,
        ..IdentityStackError::default()
    };

    let encoded = error.encode_to_vec();
    let decoded_result = IdentityStackError::decode(&mut encoded.as_slice());
    assert!(decoded_result.is_ok());
    let decoded = match decoded_result {
        Ok(decoded) => decoded,
        Err(_) => return,
    };

    assert_eq!(decoded.domain.to_i32(), 99);
    assert!(IdentityStackErrorDomain::from_i32(99).is_none());
}

#[test]
fn identity_stack_error_json_encoding_uses_stable_field_names() {
    let error = IdentityStackError {
        domain: EnumValue::from(
            IdentityStackErrorDomain::IDENTITY_STACK_ERROR_DOMAIN_IDENTITY_CORE,
        ),
        reason_code: 1,
        correlation_id: "corr_01".to_owned(),
        ..IdentityStackError::default()
    };

    let serialized_result = serde_json::to_value(error);
    assert!(serialized_result.is_ok());
    let serialized = match serialized_result {
        Ok(value) => value,
        Err(_) => return,
    };

    assert_eq!(
        serialized,
        json!({
            "domain": "IDENTITY_STACK_ERROR_DOMAIN_IDENTITY_CORE",
            "reasonCode": 1,
            "correlationId": "corr_01"
        })
    );
}
