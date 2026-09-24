// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::SdJwtEnvelopeError;
use reallyme_ssi_proto::generated::proto::reallyme::identity_core::v1::IdentityCoreErrorReason;

#[test]
fn sd_jwt_error_maps_to_identity_core_proto_reason() {
    assert_eq!(
        IdentityCoreErrorReason::from(SdJwtEnvelopeError::InvalidCompactSerialization),
        IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_SD_JWT_MALFORMED_COMPACT
    );
    assert_eq!(
        IdentityCoreErrorReason::from(SdJwtEnvelopeError::UnsupportedHashAlgorithm),
        IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_SD_JWT_UNSUPPORTED_HASH_ALGORITHM
    );
}
