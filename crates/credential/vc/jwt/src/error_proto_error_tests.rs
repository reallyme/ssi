// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::VcJwtError;
use reallyme_ssi_proto::generated::proto::reallyme::identity_core::v1::IdentityCoreErrorReason;

#[test]
fn vc_jwt_errors_map_to_stable_proto_reasons() {
    let cases = [
        (
            VcJwtError::Jwt,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_VC_JWT_JWT,
        ),
        (
            VcJwtError::InvalidPayload,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_VC_JWT_INVALID_PAYLOAD,
        ),
        (
            VcJwtError::Base64Url,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_VC_JWT_BASE64URL,
        ),
        (
            VcJwtError::VcCore,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_VC_JWT_CORE,
        ),
        (
            VcJwtError::MissingField,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_VC_JWT_MISSING_FIELD,
        ),
        (
            VcJwtError::InvalidVerificationTime,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_VC_JWT_INVALID_PAYLOAD,
        ),
        (
            VcJwtError::InvalidTemporalClaim,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_VC_JWT_INVALID_PAYLOAD,
        ),
        (
            VcJwtError::CredentialExpired,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_VC_JWT_INVALID_PAYLOAD,
        ),
        (
            VcJwtError::CredentialNotYetValid,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_VC_JWT_INVALID_PAYLOAD,
        ),
    ];

    for (error, expected) in cases {
        assert_eq!(IdentityCoreErrorReason::from(error), expected);
    }
}
