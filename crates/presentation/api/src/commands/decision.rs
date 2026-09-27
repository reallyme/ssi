// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Aggregate the mandatory presentation checks into a fail-closed decision.

use super::{PresentationCheckOutcome, PresentationCheckResult, PresentationDecision};

pub(super) fn decision_from_checks(checks: &[PresentationCheckResult]) -> PresentationDecision {
    let mut has_indeterminate = false;
    for check in checks {
        if !check.mandatory && check.outcome != PresentationCheckOutcome::Fail {
            continue;
        }
        match check.outcome {
            PresentationCheckOutcome::Fail => return PresentationDecision::Deny,
            PresentationCheckOutcome::Indeterminate | PresentationCheckOutcome::Skipped => {
                has_indeterminate = true;
            }
            PresentationCheckOutcome::Pass => {}
        }
    }

    if has_indeterminate {
        PresentationDecision::Indeterminate
    } else {
        PresentationDecision::Allow
    }
}
