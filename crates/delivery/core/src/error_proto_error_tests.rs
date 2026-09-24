// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::DeliveryError;
use reallyme_ssi_proto::generated::proto::reallyme::identity_core::v1::IdentityCoreErrorReason;

#[test]
fn delivery_errors_map_to_stable_proto_reasons() {
    let cases = [
        (
            DeliveryError::InvalidPayload,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_DELIVERY_INVALID_PAYLOAD,
        ),
        (
            DeliveryError::UnsupportedTarget,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_DELIVERY_UNSUPPORTED_TARGET,
        ),
        (
            DeliveryError::InvalidIntent,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_DELIVERY_INVALID_INTENT,
        ),
        (
            DeliveryError::PayloadTooLarge,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_DELIVERY_PAYLOAD_TOO_LARGE,
        ),
        (
            DeliveryError::Expired,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_DELIVERY_EXPIRED,
        ),
    ];

    for (error, expected) in cases {
        assert_eq!(IdentityCoreErrorReason::from(error), expected);
    }
}
