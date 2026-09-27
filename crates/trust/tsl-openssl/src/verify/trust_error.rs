// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::error::TslSignerTrustFailureReason;

pub(super) const fn map_trust_failure(
    error: reallyme_trust_core::TrustError,
) -> TslSignerTrustFailureReason {
    match error {
        reallyme_trust_core::TrustError::NoValidPath => TslSignerTrustFailureReason::NoValidPath,
        reallyme_trust_core::TrustError::InvalidTime => TslSignerTrustFailureReason::InvalidTime,
        reallyme_trust_core::TrustError::ChainLinkPolicy(_) => {
            TslSignerTrustFailureReason::ChainLinkPolicy
        }
        reallyme_trust_core::TrustError::InvalidSignature => {
            TslSignerTrustFailureReason::InvalidSignature
        }
        reallyme_trust_core::TrustError::Revoked => TslSignerTrustFailureReason::Revoked,
        reallyme_trust_core::TrustError::StatusFailure => {
            TslSignerTrustFailureReason::StatusFailure
        }
        reallyme_trust_core::TrustError::Internal
        | reallyme_trust_core::TrustError::PurposePolicyMismatch => {
            TslSignerTrustFailureReason::Internal
        }
        reallyme_trust_core::TrustError::ResourceLimit(_) => {
            TslSignerTrustFailureReason::ResourceLimit
        }
        _ => TslSignerTrustFailureReason::Internal,
    }
}
