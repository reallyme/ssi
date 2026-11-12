// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_ssi_proto::generated::proto::reallyme::identity_core::v1::IdentityCoreErrorReason;
use reallyme_vp_policy::{PolicyDecision, VpPolicyError};

use super::map_policy_decision;
use crate::error::VpValidationError;

#[test]
fn explicit_acceptance_succeeds() {
    assert!(map_policy_decision(PolicyDecision::Accept).is_ok());
}

#[test]
fn rejection_preserves_the_typed_policy_reason() {
    let result = map_policy_decision(PolicyDecision::Reject(vec![VpPolicyError::InvalidBinding]));
    assert!(
        matches!(result, Err(VpValidationError::PolicyRejected(reasons))
        if reasons == vec![VpPolicyError::InvalidBinding])
    );
}

#[test]
fn unsupported_decision_maps_to_a_stable_policy_violation() {
    assert_eq!(
        IdentityCoreErrorReason::from(&VpValidationError::UnsupportedPolicyDecision),
        IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_POLICY_VIOLATION,
    );
}
