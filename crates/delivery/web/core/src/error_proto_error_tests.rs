// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::WebDeliveryError;
use identity_presentation_delivery_core::DeliveryError;
use reallyme_ssi_proto::generated::proto::reallyme::identity_core::v1::IdentityCoreErrorReason;

#[test]
fn web_delivery_errors_map_to_stable_proto_reasons() {
    let cases = [
        (
            WebDeliveryError::Delivery(DeliveryError::InvalidPayload),
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_DELIVERY_INVALID_PAYLOAD,
        ),
        (
            WebDeliveryError::InvalidUrl,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_WEB_DELIVERY_INVALID_URL,
        ),
        (
            WebDeliveryError::Serialization,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_WEB_DELIVERY_SERIALIZATION,
        ),
        (
            WebDeliveryError::SigningFailed,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_WEB_DELIVERY_SIGNING_FAILED,
        ),
        (
            WebDeliveryError::UnsupportedPayload,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_WEB_DELIVERY_UNSUPPORTED_PAYLOAD,
        ),
        (
            WebDeliveryError::InvalidPayload,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_WEB_DELIVERY_INVALID_PAYLOAD,
        ),
    ];

    for (error, expected) in cases {
        assert_eq!(IdentityCoreErrorReason::from(error), expected);
    }
}
