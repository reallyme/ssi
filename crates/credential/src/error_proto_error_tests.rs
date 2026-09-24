// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{
    CredentialCanonicalReason, CredentialError, CredentialInvalidReason, CredentialSignatureReason,
    CredentialStatusReason,
};
use reallyme_ssi_proto::generated::proto::reallyme::identity_core::v1::IdentityCoreErrorReason;

#[test]
fn credential_invalid_reason_maps_to_identity_core_proto_reason() {
    assert_eq!(
        IdentityCoreErrorReason::from(CredentialInvalidReason::ProfileClaimsetMismatch),
        IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_CREDENTIAL_PROFILE_MISMATCH
    );
    assert_eq!(
        IdentityCoreErrorReason::from(CredentialInvalidReason::InvalidIssuerSignature),
        IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_CREDENTIAL_INVALID_ISSUER_SIGNATURE
    );
}

#[test]
fn credential_error_maps_nested_reasons_to_identity_core_proto_reason() {
    assert_eq!(
            IdentityCoreErrorReason::from(CredentialError::Signature(
                CredentialSignatureReason::UnsupportedAlgorithm
            )),
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_CREDENTIAL_SIGNATURE_UNSUPPORTED_ALGORITHM
        );
    assert_eq!(
        IdentityCoreErrorReason::from(CredentialError::Status(CredentialStatusReason::Unavailable)),
        IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_CREDENTIAL_STATUS_UNAVAILABLE
    );
    assert_eq!(
        IdentityCoreErrorReason::from(CredentialError::Canonical(
            CredentialCanonicalReason::Encoding
        )),
        IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_CANONICALIZATION_FAILED
    );
}
