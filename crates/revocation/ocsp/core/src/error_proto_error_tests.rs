// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{IdentityCoreErrorReason, OcspError};

#[test]
fn ocsp_error_maps_to_identity_core_proto_reason() {
    assert_eq!(
        IdentityCoreErrorReason::from(OcspError::Revoked),
        IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_CREDENTIAL_STATUS_REVOKED
    );
    assert_eq!(
        IdentityCoreErrorReason::from(OcspError::InvalidResponse),
        IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_CREDENTIAL_STATUS_INVALID_EVIDENCE
    );
    assert_eq!(
        IdentityCoreErrorReason::from(OcspError::Unavailable),
        IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_CREDENTIAL_STATUS_UNAVAILABLE
    );
}
