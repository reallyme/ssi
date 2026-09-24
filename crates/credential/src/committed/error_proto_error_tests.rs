// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::VcError;
use reallyme_ssi_proto::generated::proto::reallyme::identity_core::v1::IdentityCoreErrorReason;

#[test]
fn vc_core_errors_map_to_stable_proto_reasons() {
    let cases = [
        (
            VcError::Canonicalization,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_VC_CANONICALIZATION,
        ),
        (
            VcError::InvalidCredential,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_VC_INVALID_CREDENTIAL,
        ),
        (
            VcError::UnsupportedProfile,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_VC_UNSUPPORTED_PROFILE,
        ),
        (
            VcError::EntropyUnavailable,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_VC_API_ISSUANCE_FAILED,
        ),
    ];

    for (error, expected) in cases {
        assert_eq!(IdentityCoreErrorReason::from(error), expected);
    }
}
