// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::SingleDomainValidationError;
use reallyme_did_core::validate::DomainVerificationError;
use reallyme_ssi_proto::generated::proto::reallyme::identity_core::v1::IdentityCoreErrorReason;

#[test]
fn single_domain_validation_error_maps_to_identity_core_proto_reason() {
    assert_eq!(
        IdentityCoreErrorReason::from(SingleDomainValidationError::VerificationFailed),
        IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_DID_INVALID_DOMAIN
    );
    assert_eq!(
        IdentityCoreErrorReason::from(SingleDomainValidationError::Verification(
            DomainVerificationError::UnsupportedMethod
        )),
        IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_UNSUPPORTED_FORMAT
    );
}
