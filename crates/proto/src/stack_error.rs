// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! IdentityStackError adapters for identity-core-owned reason codes.
//!
//! Buffa can retain unknown signed enum values in memory, while the shared
//! stack envelope uses an unsigned wire field. Unknown non-negative values
//! remain intact for forward compatibility. Negative values map to the stable
//! unspecified code and must be handled as an unknown, fail-closed reason.

use crate::generated::proto::reallyme::identity::common::v1::{
    IdentityStackError, IdentityStackErrorDomain,
};
use buffa::EnumValue;

use crate::generated::proto::reallyme::identity_core::v1::IdentityCoreErrorReason;

/// The stack domain owned by this repository's public identity-core error enum.
pub const IDENTITY_CORE_STACK_ERROR_DOMAIN: IdentityStackErrorDomain =
    IdentityStackErrorDomain::IDENTITY_STACK_ERROR_DOMAIN_IDENTITY_CORE;

/// Converts a known identity-core reason into the neutral stack error envelope.
///
/// The resulting envelope preserves origin as `IDENTITY_CORE`; higher protocol
/// layers may still normalize deliberately into their own domain when their
/// public behavior needs a protocol-level reason.
#[must_use]
pub fn identity_core_stack_error(reason: IdentityCoreErrorReason) -> IdentityStackError {
    identity_core_stack_error_with_correlation_id(reason, String::new())
}

/// Converts a known identity-core reason into the stack envelope with a
/// caller-supplied non-PII correlation identifier.
#[must_use]
pub fn identity_core_stack_error_with_correlation_id(
    reason: IdentityCoreErrorReason,
    correlation_id: impl Into<String>,
) -> IdentityStackError {
    identity_core_stack_error_from_enum_value(EnumValue::from(reason), correlation_id)
}

/// Converts a Buffa enum value into the stack envelope while preserving unknown
/// non-negative numeric reason codes.
///
/// Negative values are not representable on the wire and are reported as
/// `IDENTITY_CORE_ERROR_REASON_UNSPECIFIED`.
///
/// This is useful at decode/forwarding boundaries: receivers can fail closed on
/// an unknown identity-core reason while retaining the exact numeric value for
/// diagnostics and future compatibility.
#[must_use]
pub fn identity_core_stack_error_from_enum_value(
    reason: EnumValue<IdentityCoreErrorReason>,
    correlation_id: impl Into<String>,
) -> IdentityStackError {
    IdentityStackError {
        domain: EnumValue::from(IDENTITY_CORE_STACK_ERROR_DOMAIN),
        reason_code: reason_code_from_i32(reason.to_i32()),
        correlation_id: correlation_id.into(),
        ..IdentityStackError::default()
    }
}

/// Maps a Buffa enum value onto the unsigned wire reason code.
///
/// Non-negative values, including unknown future reasons, are preserved
/// exactly. Negative values cannot be represented in `reason_code` and are
/// mapped explicitly to `IDENTITY_CORE_ERROR_REASON_UNSPECIFIED`, which
/// receivers must treat as a fail-closed unknown reason.
fn reason_code_from_i32(value: i32) -> u32 {
    match u32::try_from(value) {
        Ok(code) => code,
        Err(_) => UNSPECIFIED_REASON_CODE,
    }
}

/// Wire value of `IDENTITY_CORE_ERROR_REASON_UNSPECIFIED`; proto3 reserves
/// zero for the unspecified member of every enum.
const UNSPECIFIED_REASON_CODE: u32 = 0;

impl From<IdentityCoreErrorReason> for IdentityStackError {
    fn from(reason: IdentityCoreErrorReason) -> Self {
        identity_core_stack_error(reason)
    }
}
