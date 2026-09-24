// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{IdentityCoreErrorReason, OcspOpenSslError};

#[test]
fn ocsp_openssl_error_maps_to_identity_core_proto_reason() {
    assert_eq!(
        IdentityCoreErrorReason::from(OcspOpenSslError::InvalidDer),
        IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_CREDENTIAL_STATUS_INVALID_EVIDENCE
    );
    assert_eq!(
        IdentityCoreErrorReason::from(OcspOpenSslError::BadSignature),
        IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_CREDENTIAL_STATUS_INVALID_SIGNATURE
    );
    assert_eq!(
        IdentityCoreErrorReason::from(OcspOpenSslError::Backend),
        IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_CREDENTIAL_STATUS_UNAVAILABLE
    );
}
