// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{ClaimValueErrorReason, VcApiError};
use reallyme_credential::committed::error::VcError;
use reallyme_ssi_proto::generated::proto::reallyme::identity_core::v1::IdentityCoreErrorReason;

#[test]
fn claim_value_reasons_map_to_stable_proto_reasons() {
    let cases = [
            (
                ClaimValueErrorReason::Unspecified,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_VC_CLAIM_VALUE_UNSPECIFIED,
            ),
            (
                ClaimValueErrorReason::ExpectedString,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_VC_CLAIM_VALUE_EXPECTED_STRING,
            ),
            (
                ClaimValueErrorReason::ExpectedBoolean,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_VC_CLAIM_VALUE_EXPECTED_BOOLEAN,
            ),
            (
                ClaimValueErrorReason::ExpectedInteger,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_VC_CLAIM_VALUE_EXPECTED_INTEGER,
            ),
            (
                ClaimValueErrorReason::ExpectedSignedInteger,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_VC_CLAIM_VALUE_EXPECTED_SIGNED_INTEGER,
            ),
            (
                ClaimValueErrorReason::ExpectedUnsignedInteger,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_VC_CLAIM_VALUE_EXPECTED_UNSIGNED_INTEGER,
            ),
            (
                ClaimValueErrorReason::ExpectedNumber,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_VC_CLAIM_VALUE_EXPECTED_NUMBER,
            ),
            (
                ClaimValueErrorReason::ExpectedDecimal,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_VC_CLAIM_VALUE_EXPECTED_DECIMAL,
            ),
            (
                ClaimValueErrorReason::ExpectedBytes,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_VC_CLAIM_VALUE_EXPECTED_BYTES,
            ),
            (
                ClaimValueErrorReason::ExpectedDate,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_VC_CLAIM_VALUE_EXPECTED_DATE,
            ),
            (
                ClaimValueErrorReason::ExpectedNull,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_VC_CLAIM_VALUE_EXPECTED_NULL,
            ),
            (
                ClaimValueErrorReason::ExpectedObject,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_VC_CLAIM_VALUE_EXPECTED_OBJECT,
            ),
            (
                ClaimValueErrorReason::ExpectedArray,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_VC_CLAIM_VALUE_EXPECTED_ARRAY,
            ),
        ];

    for (reason, expected) in cases {
        assert_eq!(IdentityCoreErrorReason::from(reason), expected);
    }
}

#[test]
fn vc_api_errors_delegate_or_map_to_stable_proto_reasons() {
    assert_eq!(
        IdentityCoreErrorReason::from(VcApiError::UnsupportedProfile),
        IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_VC_API_UNSUPPORTED_PROFILE
    );
    assert_eq!(
        IdentityCoreErrorReason::from(VcApiError::VcCore(VcError::InvalidCredential)),
        IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_VC_INVALID_CREDENTIAL
    );
    assert_eq!(
        IdentityCoreErrorReason::from(VcApiError::InvalidClaimValue(
            ClaimValueErrorReason::ExpectedString
        )),
        IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_VC_CLAIM_VALUE_EXPECTED_STRING
    );
}
