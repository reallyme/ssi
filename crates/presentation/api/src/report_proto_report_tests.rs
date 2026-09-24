// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{VpFailureClass, VpReportProtoError, VpVerificationOutcome, VpVerificationReport};
use buffa::{EnumValue, Enumeration};
use reallyme_disclosure_policy::VpPolicyError;
use reallyme_ssi_proto::generated::proto::identity::presentation::v1 as presentation_pb;
use reallyme_ssi_proto::generated::proto::reallyme::identity_core::v1::IdentityCoreErrorReason;

#[test]
fn vp_report_enums_round_trip_through_proto_values() {
    let outcome_proto =
        presentation_pb::VpVerificationOutcome::from(VpVerificationOutcome::Rejected);
    assert_eq!(outcome_proto.to_i32(), 2);
    assert_eq!(
        VpVerificationOutcome::try_from(EnumValue::from(outcome_proto)),
        Ok(VpVerificationOutcome::Rejected)
    );

    let class_proto = presentation_pb::VpFailureClass::from(VpFailureClass::Status);
    assert_eq!(class_proto.to_i32(), 8);
    assert_eq!(
        VpFailureClass::try_from(EnumValue::from(class_proto)),
        Ok(VpFailureClass::Status)
    );
}

#[test]
fn vp_report_proto_unknown_values_fail_closed() {
    assert_eq!(
        VpVerificationOutcome::try_from(EnumValue::<presentation_pb::VpVerificationOutcome>::from(
            65_535
        )),
        Err(VpReportProtoError::UnknownOutcome)
    );
    assert_eq!(
        VpFailureClass::try_from(EnumValue::<presentation_pb::VpFailureClass>::from(65_535)),
        Err(VpReportProtoError::UnknownFailureClass)
    );
    assert_eq!(
        VpFailureClass::try_from(EnumValue::from(
            presentation_pb::VpFailureClass::VP_FAILURE_CLASS_UNSPECIFIED
        )),
        Err(VpReportProtoError::UnknownFailureClass)
    );
}

#[test]
fn vp_report_proto_conversion_error_maps_to_identity_core_reason() {
    assert_eq!(
        IdentityCoreErrorReason::from(VpReportProtoError::UnknownOutcome),
        IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_INVALID_ENCODING
    );
}

#[test]
fn vp_report_converts_to_proto_summary() {
    let report = VpVerificationReport::rejected(vec![
        VpPolicyError::InvalidBinding,
        VpPolicyError::CredentialRevoked,
    ]);

    let proto = report.to_proto_summary();

    assert_eq!(
        proto.outcome.to_i32(),
        presentation_pb::VpVerificationOutcome::VP_VERIFICATION_OUTCOME_REJECTED.to_i32()
    );
    let class_codes: Vec<i32> = proto
        .failure_classes
        .iter()
        .map(EnumValue::to_i32)
        .collect();
    assert_eq!(class_codes, vec![1, 8]);
}
