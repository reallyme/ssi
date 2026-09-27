// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use envelopes_x509::X509Chain;

use super::{TrustDecision, TrustEvidence, TrustFailureReason, TrustOutcome};

impl TrustDecision {
    /// Returns the authoritative three-state outcome.
    #[must_use]
    pub const fn outcome(&self) -> TrustOutcome {
        self.outcome
    }

    /// Returns whether trust was conclusively established.
    #[must_use]
    pub const fn is_accepted(&self) -> bool {
        self.accepted
    }

    /// Returns the authenticated leaf-to-anchor chain for a trusted decision.
    #[must_use]
    pub const fn chain(&self) -> Option<&X509Chain> {
        self.chain.as_ref()
    }

    /// Returns the stable failure reasons retained by the evaluator.
    #[must_use]
    pub fn failures(&self) -> &[TrustFailureReason] {
        &self.failures
    }

    /// Returns the audit evidence retained by the evaluator.
    #[must_use]
    pub const fn evidence(&self) -> &TrustEvidence {
        &self.evidence
    }
}
