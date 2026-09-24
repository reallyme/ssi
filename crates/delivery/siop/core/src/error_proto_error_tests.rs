// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::SiopDeliveryError;
use reallyme_ssi_proto::generated::proto::reallyme::identity_core::v1::IdentityCoreErrorReason;

#[test]
fn siop_delivery_errors_map_to_stable_proto_reasons() {
    let cases = [
        (
            SiopDeliveryError::InvalidInput,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_SIOP_DELIVERY_INVALID_INPUT,
        ),
        (
            SiopDeliveryError::Expired,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_SIOP_DELIVERY_EXPIRED,
        ),
    ];

    for (error, expected) in cases {
        assert_eq!(IdentityCoreErrorReason::from(error), expected);
    }
}
