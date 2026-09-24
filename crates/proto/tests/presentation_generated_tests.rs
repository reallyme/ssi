// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Tests for generated presentation protobuf bindings.

#![cfg(feature = "generated")]
#![allow(missing_docs)]

use buffa::{EnumValue, Enumeration, Message};
use reallyme_ssi_proto::generated::proto::identity::presentation::v1::{
    __buffa::oneof::presentation::Kind, Presentation, SdJwtVcPresentation, VpFailureClass,
    VpVerificationOutcome, VpVerificationReport,
};

#[test]
fn presentation_proto_round_trips_with_buffa() {
    let presentation = Presentation {
        kind: Some(Kind::SdJwtVc(Box::new(SdJwtVcPresentation {
            sd_jwt: "header.payload.signature".to_owned(),
            disclosures: vec!["disclosure".to_owned()],
            kb_jwt: Some("kb.header.payload.signature".to_owned()),
            vct: Some("eu.pid.v1".to_owned()),
            envelope_hash: Some(vec![1u8; 32]),
            ..SdJwtVcPresentation::default()
        }))),
        ..Presentation::default()
    };

    let encoded = presentation.encode_to_vec();
    let decoded_result = Presentation::decode(&mut encoded.as_slice());
    assert!(decoded_result.is_ok());
    let decoded = match decoded_result {
        Ok(decoded) => decoded,
        Err(_) => return,
    };

    let decoded_kind = decoded.kind;
    assert!(matches!(decoded_kind, Some(Kind::SdJwtVc(_))));
    let Some(Kind::SdJwtVc(decoded_sd_jwt)) = decoded_kind else {
        return;
    };

    assert_eq!(decoded_sd_jwt.sd_jwt, "header.payload.signature");
    assert_eq!(decoded_sd_jwt.disclosures, vec!["disclosure".to_owned()]);
    assert_eq!(decoded_sd_jwt.envelope_hash, Some(vec![1u8; 32]));
}

#[test]
fn vp_report_reason_codes_are_stable() {
    assert_eq!(
        VpVerificationOutcome::VP_VERIFICATION_OUTCOME_ACCEPTED.to_i32(),
        1
    );
    assert_eq!(
        VpVerificationOutcome::VP_VERIFICATION_OUTCOME_REJECTED.to_i32(),
        2
    );
    assert_eq!(VpFailureClass::VP_FAILURE_CLASS_BINDING.to_i32(), 1);
    assert_eq!(VpFailureClass::VP_FAILURE_CLASS_STATUS.to_i32(), 8);
    assert_eq!(VpFailureClass::VP_FAILURE_CLASS_ZK.to_i32(), 11);
}

#[test]
fn vp_report_unknown_enum_values_remain_detectable() {
    let unknown = EnumValue::<VpFailureClass>::from(65_535);

    assert_eq!(unknown.to_i32(), 65_535);
    assert!(VpFailureClass::from_i32(unknown.to_i32()).is_none());
}

#[test]
fn vp_report_proto_json_encoding_is_stable() {
    let report = VpVerificationReport {
        outcome: EnumValue::from(VpVerificationOutcome::VP_VERIFICATION_OUTCOME_REJECTED),
        failure_classes: vec![
            EnumValue::from(VpFailureClass::VP_FAILURE_CLASS_BINDING),
            EnumValue::from(VpFailureClass::VP_FAILURE_CLASS_STATUS),
        ],
        ..VpVerificationReport::default()
    };

    let serialized_result = serde_json::to_value(report);
    assert!(serialized_result.is_ok());
    let serialized = match serialized_result {
        Ok(value) => value,
        Err(_) => return,
    };

    assert_eq!(
        serialized,
        serde_json::json!({
            "outcome": "VP_VERIFICATION_OUTCOME_REJECTED",
            "failureClasses": [
                "VP_FAILURE_CLASS_BINDING",
                "VP_FAILURE_CLASS_STATUS"
            ]
        })
    );
}
