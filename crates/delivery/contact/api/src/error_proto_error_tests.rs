// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::ContactApiError;
use reallyme_ssi_proto::generated::proto::reallyme::identity_core::v1::IdentityCoreErrorReason;

#[test]
fn contact_api_errors_map_to_stable_proto_reasons() {
    let cases = [
            (
                ContactApiError::InvalidInput,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_CONTACT_API_INVALID_INPUT,
            ),
            (
                ContactApiError::Serialization,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_CONTACT_API_SERIALIZATION,
            ),
            (
                ContactApiError::Expired,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_CONTACT_API_EXPIRED,
            ),
            (
                ContactApiError::SessionTranscriptMismatch,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_CONTACT_API_SESSION_TRANSCRIPT_MISMATCH,
            ),
        ];

    for (error, expected) in cases {
        assert_eq!(IdentityCoreErrorReason::from(error), expected);
    }
}
