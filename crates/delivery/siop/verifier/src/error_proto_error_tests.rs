// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::SiopVerifierError;
use reallyme_ssi_proto::generated::proto::reallyme::identity_core::v1::IdentityCoreErrorReason;

#[test]
fn siop_verifier_errors_map_to_stable_proto_reasons() {
    let cases = [
        (
            SiopVerifierError::InvalidInput,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_SIOP_VERIFIER_INVALID_INPUT,
        ),
        (
            SiopVerifierError::InvalidSignature,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_SIOP_VERIFIER_INVALID_SIGNATURE,
        ),
        (
            SiopVerifierError::Expired,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_SIOP_VERIFIER_EXPIRED,
        ),
        (
            SiopVerifierError::AudienceMismatch,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_SIOP_VERIFIER_AUDIENCE_MISMATCH,
        ),
        (
            SiopVerifierError::NonceMismatch,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_SIOP_VERIFIER_NONCE_MISMATCH,
        ),
    ];

    for (error, expected) in cases {
        assert_eq!(IdentityCoreErrorReason::from(error), expected);
    }
}
