// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

impl PresentationVerificationResult {
    /// Whether all mandatory checks passed.
    #[must_use]
    pub const fn is_valid(&self) -> bool {
        self.valid
    }

    /// Aggregate verification decision.
    #[must_use]
    pub const fn decision(&self) -> PresentationDecision {
        self.decision
    }

    /// Presentation check rows.
    #[must_use]
    pub fn presentation_checks(&self) -> &[PresentationCheckResult] {
        self.presentation_checks.as_slice()
    }

    /// Credential-level summary rows.
    #[must_use]
    pub fn credential_results(&self) -> &[PresentationCredentialResult] {
        self.credential_results.as_slice()
    }

    /// Disclosed claim facts.
    #[must_use]
    pub fn disclosed_claims(&self) -> &[PresentationDisclosureFact] {
        self.disclosed_claims.as_slice()
    }

    /// Stable warning codes.
    #[must_use]
    pub fn warnings(&self) -> &[PresentationCommandIssue] {
        self.warnings.as_slice()
    }

    /// Stable error codes.
    #[must_use]
    pub fn errors(&self) -> &[PresentationCommandIssue] {
        self.errors.as_slice()
    }
}
