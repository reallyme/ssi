// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_vp_policy::PolicyDecision;

use crate::error::VpValidationError;

/// Map policy decisions into validator-level errors.
pub fn map_policy_decision(decision: PolicyDecision) -> Result<(), VpValidationError> {
    match decision {
        PolicyDecision::Accept => Ok(()),
        PolicyDecision::Reject(errs) => Err(VpValidationError::PolicyRejected(errs)),
        // Only an explicitly understood acceptance can authorize a presentation.
        _ => Err(VpValidationError::UnsupportedPolicyDecision),
    }
}

#[cfg(test)]
#[path = "oidc_error_tests.rs"]
mod tests;
