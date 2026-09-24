// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{CrlError, IdentityCoreErrorReason};

#[test]
fn crl_error_maps_to_identity_core_proto_reason() {
    assert_eq!(
        IdentityCoreErrorReason::from(CrlError::InvalidCrl),
        IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_CREDENTIAL_STATUS_INVALID_EVIDENCE
    );
    assert_eq!(
        IdentityCoreErrorReason::from(CrlError::MissingIssuer),
        IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TRUST_CHAIN_INVALID
    );
    assert_eq!(
        IdentityCoreErrorReason::from(CrlError::Unsupported),
        IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_REVOCATION_STATUS_UNSUPPORTED
    );
}
