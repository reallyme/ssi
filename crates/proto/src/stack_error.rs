// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! IdentityStackError adapters for identity-core-owned reason codes.

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
/// numeric reason codes.
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

fn reason_code_from_i32(value: i32) -> u32 {
    u32::try_from(value).unwrap_or_default()
}

impl From<IdentityCoreErrorReason> for IdentityStackError {
    fn from(reason: IdentityCoreErrorReason) -> Self {
        identity_core_stack_error(reason)
    }
}
