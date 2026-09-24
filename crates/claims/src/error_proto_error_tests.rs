// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{ClaimsError, ClaimsInvalidReason};
use reallyme_ssi_proto::generated::proto::reallyme::identity_core::v1::IdentityCoreErrorReason;

#[test]
fn claims_invalid_reason_maps_to_identity_core_proto_reason() {
    assert_eq!(
        IdentityCoreErrorReason::from(ClaimsInvalidReason::InvalidClaimPath),
        IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_CLAIMS_INVALID_CLAIM_PATH
    );
    assert_eq!(
        IdentityCoreErrorReason::from(ClaimsInvalidReason::ClaimValueLimitExceeded),
        IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_CLAIMS_VALUE_LIMIT_EXCEEDED
    );
}

#[test]
fn claims_error_maps_to_identity_core_proto_reason() {
    assert_eq!(
        IdentityCoreErrorReason::from(ClaimsError::PredicateNotAllowed),
        IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_CLAIMS_PREDICATE_NOT_ALLOWED
    );
}
