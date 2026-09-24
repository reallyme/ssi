// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::ContactValidationError;
use reallyme_ssi_proto::generated::proto::reallyme::identity_core::v1::IdentityCoreErrorReason;

#[test]
fn contact_validation_errors_map_to_stable_proto_reasons() {
    let cases = [
            (
                ContactValidationError::InvalidInput,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_CONTACT_VALIDATION_INVALID_INPUT,
            ),
            (
                ContactValidationError::Serialization,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_CONTACT_VALIDATION_SERIALIZATION,
            ),
            (
                ContactValidationError::Expired,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_CONTACT_VALIDATION_EXPIRED,
            ),
            (
                ContactValidationError::SessionTranscriptMismatch,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_CONTACT_VALIDATION_SESSION_TRANSCRIPT_MISMATCH,
            ),
        ];

    for (error, expected) in cases {
        assert_eq!(IdentityCoreErrorReason::from(error), expected);
    }
}
