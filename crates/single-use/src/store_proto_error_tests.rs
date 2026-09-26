// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{IdentityCoreErrorReason, SingleUseError};

#[test]
fn single_use_errors_map_to_stable_proto_reasons() {
    let cases = [
        (
            SingleUseError::Rejected,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_SINGLE_USE_REJECTED,
        ),
        (
            SingleUseError::Unavailable,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_SINGLE_USE_UNAVAILABLE,
        ),
        (
            SingleUseError::InvalidKey,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_SINGLE_USE_INVALID_KEY,
        ),
        (
            SingleUseError::CapacityExceeded,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_SINGLE_USE_UNAVAILABLE,
        ),
        (
            SingleUseError::InvalidExpiry,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_SINGLE_USE_INVALID_KEY,
        ),
    ];

    for (error, expected) in cases {
        assert_eq!(IdentityCoreErrorReason::from(error), expected);
    }
}
