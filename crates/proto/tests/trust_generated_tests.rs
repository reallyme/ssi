// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Tests for generated trust protobuf bindings.

#![cfg(feature = "generated")]
#![allow(missing_docs)]

use buffa::{EnumValue, Enumeration, Message};
use reallyme_ssi_proto::generated::proto::identity::trust::v1::{
    AuthorizationPurpose, TrustDecision, TrustDecisionFailure, TrustPolicyId, TrustPurpose,
};

#[test]
fn trust_proto_enum_values_are_stable() {
    assert_eq!(
        TrustDecisionFailure::TRUST_DECISION_FAILURE_NO_VALID_PATH.to_i32(),
        1
    );
    assert_eq!(
        TrustDecisionFailure::TRUST_DECISION_FAILURE_SIGNATURE.to_i32(),
        5
    );
    assert_eq!(
        AuthorizationPurpose::AUTHORIZATION_PURPOSE_QEAA_ISSUER.to_i32(),
        1
    );
    assert_eq!(
        AuthorizationPurpose::AUTHORIZATION_PURPOSE_QSEAL_SIGNER.to_i32(),
        3
    );
    assert_eq!(
        TrustPurpose::TRUST_PURPOSE_WALLET_RELYING_PARTY_REGISTRY_SIGNING.to_i32(),
        15
    );
    assert_eq!(
        TrustPolicyId::TRUST_POLICY_ID_EUDI_TS5_REGISTRY_RESPONSE_SIGNING_V1.to_i32(),
        15
    );
}

#[test]
fn trust_proto_unknown_enum_numbers_remain_detectable() {
    let unknown = EnumValue::<TrustDecisionFailure>::from(65_535);

    assert_eq!(unknown.to_i32(), 65_535);
    assert!(TrustDecisionFailure::from_i32(unknown.to_i32()).is_none());
}

#[test]
fn trust_decision_proto_round_trips_with_buffa() {
    let decision = TrustDecision {
        accepted: false,
        failures: vec![
            EnumValue::from(TrustDecisionFailure::TRUST_DECISION_FAILURE_NO_VALID_PATH),
            EnumValue::from(TrustDecisionFailure::TRUST_DECISION_FAILURE_SIGNATURE),
        ],
        ..TrustDecision::default()
    };

    let encoded = decision.encode_to_vec();
    let decoded_result = TrustDecision::decode(&mut encoded.as_slice());
    assert!(decoded_result.is_ok());
    let decoded = match decoded_result {
        Ok(decoded) => decoded,
        Err(_) => return,
    };

    assert!(!decoded.accepted);
    assert_eq!(decoded.failures.len(), 2);
}

#[test]
fn trust_decision_proto_json_is_stable() {
    let decision = TrustDecision {
        accepted: false,
        failures: vec![
            EnumValue::from(TrustDecisionFailure::TRUST_DECISION_FAILURE_NO_VALID_PATH),
            EnumValue::from(TrustDecisionFailure::TRUST_DECISION_FAILURE_SIGNATURE),
        ],
        ..TrustDecision::default()
    };

    let json_result = serde_json::to_string(&decision);
    assert!(json_result.is_ok());
    let json = match json_result {
        Ok(json) => json,
        Err(_) => return,
    };

    assert_eq!(
        json,
        r#"{"failures":["TRUST_DECISION_FAILURE_NO_VALID_PATH","TRUST_DECISION_FAILURE_SIGNATURE"]}"#
    );
}
