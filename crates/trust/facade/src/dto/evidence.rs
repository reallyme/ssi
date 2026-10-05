// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{TrustDecision, TrustDecisionEvidence, TrustSourceEvidence};
use zeroize::{Zeroize, ZeroizeOnDrop};

impl Drop for TrustDecision {
    fn drop(&mut self) {
        self.evidence.zeroize();
    }
}

impl ZeroizeOnDrop for TrustDecision {}

impl core::fmt::Debug for TrustSourceEvidence {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .write_str("TrustSourceEvidence { source_id: <redacted>, snapshot_id: <redacted> }")
    }
}

impl core::fmt::Debug for TrustDecisionEvidence {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // A leaf fingerprint can identify a credential holder. Retain the
        // evidence for callers, but never expose those bytes through logs.
        formatter
            .debug_struct("TrustDecisionEvidence")
            .field("purpose", &self.purpose)
            .field("policy_id", &self.policy_id)
            .field("evaluated_at_unix", &self.evaluated_at_unix)
            .field("source_present", &self.source.is_some())
            .field("trust_anchor", &self.trust_anchor)
            .field("certificate_status", &self.certificate_status)
            .field(
                "selected_path_certificate_count",
                &self.selected_path_certificate_sha256.len(),
            )
            .finish()
    }
}

impl Zeroize for TrustDecisionEvidence {
    fn zeroize(&mut self) {
        if let Some(source) = &mut self.source {
            source.source_id.zeroize();
            source.snapshot_id.zeroize();
        }
        self.selected_path_certificate_sha256.zeroize();
    }
}

impl Drop for TrustDecisionEvidence {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for TrustDecisionEvidence {}
