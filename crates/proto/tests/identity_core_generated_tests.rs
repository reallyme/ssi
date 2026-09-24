// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Tests for generated identity-core protobuf bindings.

#![cfg(feature = "generated")]
#![allow(missing_docs)]

use buffa::{EnumValue, Enumeration};
use reallyme_ssi_proto::generated::proto::reallyme::identity::common::v1::IdentityStackErrorDomain;
use reallyme_ssi_proto::generated::proto::reallyme::identity_core::v1::IdentityCoreErrorReason;
use reallyme_ssi_proto::stack_error::{
    identity_core_stack_error, identity_core_stack_error_from_enum_value,
    identity_core_stack_error_with_correlation_id, IDENTITY_CORE_STACK_ERROR_DOMAIN,
};

#[test]
fn identity_core_error_reason_codes_are_stable() {
    assert_eq!(
        IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_UNSUPPORTED_FORMAT.to_i32(),
        1
    );
    assert_eq!(
        IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_MDOC_UNSUPPORTED_DOCTYPE.to_i32(),
        100
    );
    assert_eq!(
        IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_SD_JWT_MALFORMED_COMPACT.to_i32(),
        200
    );
    assert_eq!(
        IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_DID_UNSUPPORTED_METHOD.to_i32(),
        300
    );
    assert_eq!(
        IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_VC_API_INVALID_COMMAND.to_i32(),
        544
    );
}

#[test]
fn identity_core_error_reason_enum_value_round_trips_known_values() {
    let value = EnumValue::from(
        IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_PRESENTATION_POLICY_NOT_SATISFIED,
    );

    assert_eq!(value.to_i32(), 502);
    assert_eq!(
        IdentityCoreErrorReason::from_i32(value.to_i32()),
        Some(IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_PRESENTATION_POLICY_NOT_SATISFIED)
    );
}

#[test]
fn identity_core_error_reason_unknown_values_remain_detectable() {
    let unknown = EnumValue::<IdentityCoreErrorReason>::from(65_535);

    assert_eq!(unknown.to_i32(), 65_535);
    assert!(IdentityCoreErrorReason::from_i32(unknown.to_i32()).is_none());
}

#[test]
fn identity_core_error_reason_json_encoding_is_stable() {
    let value =
        EnumValue::from(IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_DID_INVALID_DOCUMENT);

    let serialized_result = serde_json::to_value(value);
    assert!(serialized_result.is_ok());
    let serialized = match serialized_result {
        Ok(value) => value,
        Err(_) => return,
    };

    assert_eq!(
        serialized,
        serde_json::Value::String("IDENTITY_CORE_ERROR_REASON_DID_INVALID_DOCUMENT".to_owned())
    );
}

#[test]
fn identity_core_reason_converts_to_stack_error_domain_and_code() {
    let stack_error = identity_core_stack_error(
        IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_DID_UNSUPPORTED_METHOD,
    );

    assert_eq!(
        stack_error.domain.to_i32(),
        IdentityStackErrorDomain::IDENTITY_STACK_ERROR_DOMAIN_IDENTITY_CORE.to_i32()
    );
    assert_eq!(
        stack_error.domain.to_i32(),
        IDENTITY_CORE_STACK_ERROR_DOMAIN.to_i32()
    );
    assert_eq!(stack_error.reason_code, 300);
    assert_eq!(stack_error.correlation_id, "");
}

#[test]
fn identity_core_stack_error_includes_non_pii_correlation_id() {
    let stack_error = identity_core_stack_error_with_correlation_id(
        IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_PRESENTATION_POLICY_NOT_SATISFIED,
        "corr-identity-core-0001",
    );

    assert_eq!(
        stack_error.domain.to_i32(),
        IdentityStackErrorDomain::IDENTITY_STACK_ERROR_DOMAIN_IDENTITY_CORE.to_i32()
    );
    assert_eq!(stack_error.reason_code, 502);
    assert_eq!(stack_error.correlation_id, "corr-identity-core-0001");
}

#[test]
fn identity_core_stack_error_preserves_unknown_reason_code() {
    let stack_error = identity_core_stack_error_from_enum_value(
        EnumValue::<IdentityCoreErrorReason>::from(65_535),
        "",
    );

    assert_eq!(
        stack_error.domain.to_i32(),
        IdentityStackErrorDomain::IDENTITY_STACK_ERROR_DOMAIN_IDENTITY_CORE.to_i32()
    );
    assert_eq!(stack_error.reason_code, 65_535);
    let decoded_reason_code = match i32::try_from(stack_error.reason_code) {
        Ok(value) => value,
        Err(_) => return,
    };
    assert!(IdentityCoreErrorReason::from_i32(decoded_reason_code).is_none());
}
