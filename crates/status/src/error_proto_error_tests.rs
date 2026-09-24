// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{CredentialStatusError, CredentialStatusInvalidReason};
use reallyme_ssi_proto::generated::proto::reallyme::identity_core::v1::IdentityCoreErrorReason;

#[test]
fn status_invalid_reason_maps_to_identity_core_proto_reason() {
    assert_eq!(
        IdentityCoreErrorReason::from(CredentialStatusInvalidReason::UnsupportedPurpose),
        IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_CREDENTIAL_STATUS_UNSUPPORTED_PURPOSE
    );
    assert_eq!(
        IdentityCoreErrorReason::from(CredentialStatusInvalidReason::TooLarge),
        IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_CREDENTIAL_STATUS_TOO_LARGE
    );
}

#[test]
fn status_error_maps_to_identity_core_proto_reason() {
    assert_eq!(
        IdentityCoreErrorReason::from(CredentialStatusError::InvalidSignature),
        IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_CREDENTIAL_STATUS_INVALID_SIGNATURE
    );
}
