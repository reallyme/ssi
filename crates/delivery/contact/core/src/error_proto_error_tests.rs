// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::ContactDeliveryError;
use reallyme_ssi_proto::generated::proto::reallyme::identity_core::v1::IdentityCoreErrorReason;

#[test]
fn contact_delivery_errors_map_to_stable_proto_reasons() {
    let cases = [
        (
            ContactDeliveryError::InvalidInput,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_CONTACT_DELIVERY_INVALID_INPUT,
        ),
        (
            ContactDeliveryError::Serialization,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_CONTACT_DELIVERY_SERIALIZATION,
        ),
        (
            ContactDeliveryError::MessageTooLarge,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_CONTACT_DELIVERY_MESSAGE_TOO_LARGE,
        ),
        (
            ContactDeliveryError::FrameTooLarge,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_CONTACT_DELIVERY_FRAME_TOO_LARGE,
        ),
        (
            ContactDeliveryError::TooManyFrames,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_CONTACT_DELIVERY_TOO_MANY_FRAMES,
        ),
    ];

    for (error, expected) in cases {
        assert_eq!(IdentityCoreErrorReason::from(error), expected);
    }
}
