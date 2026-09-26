// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{CrlError, IdentityCoreErrorReason};

#[test]
fn crl_error_maps_to_identity_core_proto_reason() {
    let cases = [
        (
            CrlError::InvalidCrl,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_CREDENTIAL_STATUS_INVALID_EVIDENCE,
        ),
        (
            CrlError::TooLarge,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_CREDENTIAL_STATUS_INVALID_EVIDENCE,
        ),
        (
            CrlError::MissingIssuer,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TRUST_CHAIN_INVALID,
        ),
        (
            CrlError::IssuerMismatch,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TRUST_CHAIN_INVALID,
        ),
        (
            CrlError::BadSignature,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_CREDENTIAL_STATUS_INVALID_SIGNATURE,
        ),
        (
            CrlError::InvalidTime,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_CREDENTIAL_STATUS_INVALID_TIME_WINDOW,
        ),
        (
            CrlError::Unsupported,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_REVOCATION_STATUS_UNSUPPORTED,
        ),
        (
            CrlError::UnsupportedScope,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_REVOCATION_STATUS_UNSUPPORTED,
        ),
        (
            CrlError::UnsupportedCriticalExtension,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_REVOCATION_STATUS_UNSUPPORTED,
        ),
    ];
    for (error, expected) in cases {
        assert_eq!(IdentityCoreErrorReason::from(error), expected);
    }
}
