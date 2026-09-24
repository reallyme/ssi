// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_disclosure_policy::{evaluate, EvaluationContext, PolicyDecision, VpPolicy};

use crate::error::VpApiError;
use crate::report::VpVerificationReport;

/// Validate already-verified presentation facts against disclosure policy.
///
/// This helper returns `Ok` for both accepted and rejected policy decisions.
/// Callers can inspect the report and map failures into delivery-protocol
/// errors without losing secondary policy failures.
pub fn validate_vp(policy: &VpPolicy, ctx: &EvaluationContext<'_>) -> VpVerificationReport {
    match evaluate(policy, ctx) {
        PolicyDecision::Accept => VpVerificationReport::accepted(),
        PolicyDecision::Reject(errors) => VpVerificationReport::rejected(errors),
    }
}

/// Validate a presentation and return an error on any policy rejection.
pub fn validate_vp_strict(
    policy: &VpPolicy,
    ctx: &EvaluationContext<'_>,
) -> Result<(), VpApiError> {
    match validate_vp(policy, ctx) {
        report if report.is_accepted() => Ok(()),
        report => Err(VpApiError::PolicyRejected(report.errors)),
    }
}
