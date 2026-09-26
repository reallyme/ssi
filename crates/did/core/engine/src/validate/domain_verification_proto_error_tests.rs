// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::DomainVerificationError;
use reallyme_ssi_proto::generated::proto::reallyme::identity_core::v1::IdentityCoreErrorReason;

#[test]
fn domain_verification_error_maps_to_identity_core_proto_reason() {
    assert_eq!(
        IdentityCoreErrorReason::from(DomainVerificationError::MissingDnsBinding),
        IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_DID_INVALID_DOMAIN
    );
    assert_eq!(
        IdentityCoreErrorReason::from(DomainVerificationError::ResolveTxtFailed),
        IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_BACKEND_UNAVAILABLE
    );
    assert_eq!(
        IdentityCoreErrorReason::from(DomainVerificationError::InvalidWellKnownJson),
        IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_INVALID_ENCODING
    );
    assert_eq!(
        IdentityCoreErrorReason::from(DomainVerificationError::UnsupportedMethod),
        IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_UNSUPPORTED_FORMAT
    );
    assert_eq!(
        IdentityCoreErrorReason::from(DomainVerificationError::InvalidDomain),
        IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_DID_INVALID_DOMAIN
    );
    assert_eq!(
        IdentityCoreErrorReason::from(DomainVerificationError::BindingMismatch),
        IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_DID_INVALID_DOMAIN
    );
}
