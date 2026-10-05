// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_trust_core::TrustError;
use thiserror::Error;

/// Typed facade failures. Rejected and indeterminate trust are decision values.
#[derive(Debug, Error)]
pub enum TrustApiError {
    /// A certificate's parsed fields do not match its original DER encoding.
    #[error("certificate projection does not match DER")]
    InvalidCertificate,
    /// An input collection exceeded a fixed evaluation bound.
    #[error("trust evaluation input limit exceeded")]
    InputLimit,
    /// The core rejected an invalid evaluation configuration or resource bound.
    #[error("invalid trust evaluation configuration")]
    Core(#[from] TrustError),
    /// The core returned a value the facade cannot represent without losing evidence.
    #[error("unsupported trust decision representation")]
    UnsupportedDecision,
}
