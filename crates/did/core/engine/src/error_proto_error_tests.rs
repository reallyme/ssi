// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{CanonicalStateViolation, DidCoreError};
use reallyme_ssi_proto::generated::proto::reallyme::identity_core::v1::IdentityCoreErrorReason;

#[test]
fn did_core_error_maps_to_identity_core_proto_reason() {
    assert_eq!(
        IdentityCoreErrorReason::from(DidCoreError::InvalidCanonicalState(
            CanonicalStateViolation::UnsupportedVerificationMethodAlgorithm
        )),
        IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_UNSUPPORTED_ALGORITHM
    );
    assert_eq!(
        IdentityCoreErrorReason::from(DidCoreError::PolicyViolation),
        IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_POLICY_VIOLATION
    );
}
