// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Stable protobuf mappings for revocation and status domain errors.

use reallyme_revocation::{RevocationPolicyError, StatusCheckError};
use reallyme_ssi_proto::generated::proto::reallyme::identity_core::v1::IdentityCoreErrorReason;

#[test]
fn status_outcomes_have_distinct_stable_proto_reasons() {
    let cases = [
        (
            StatusCheckError::Unknown,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_CREDENTIAL_STATUS_UNKNOWN,
        ),
        (
            StatusCheckError::Unavailable,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_CREDENTIAL_STATUS_UNAVAILABLE,
        ),
        (
            StatusCheckError::Unsupported,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_CREDENTIAL_STATUS_UNSUPPORTED,
        ),
    ];

    for (error, expected) in cases {
        assert_eq!(IdentityCoreErrorReason::from(error), expected);
    }
}

#[test]
fn revocation_configuration_failures_have_distinct_stable_proto_reasons() {
    assert_eq!(
        IdentityCoreErrorReason::from(RevocationPolicyError::NoSources),
        IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_REVOCATION_SOURCE_NOT_CONFIGURED
    );
    assert_eq!(
        IdentityCoreErrorReason::from(RevocationPolicyError::Unavailable),
        IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_REVOCATION_SOURCES_UNAVAILABLE
    );
}
