// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use core::fmt;

use reallyme_ssi_proto::generated::proto::reallyme::identity_core::v1::IdentityCoreErrorReason;

/// Errors shared by common identity primitives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentityCoreError {
    /// Canonical data was malformed or could not be represented deterministically.
    InvalidCanonicalForm,

    /// The requested algorithm is not accepted for the current operation.
    AlgorithmNotAllowed,

    /// A policy rule rejected the operation.
    PolicyViolation,

    /// An internal invariant was violated without exposing dynamic context.
    InternalInvariant,
}

impl fmt::Display for IdentityCoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            IdentityCoreError::InvalidCanonicalForm => "invalid canonical form",
            IdentityCoreError::AlgorithmNotAllowed => "algorithm not allowed",
            IdentityCoreError::PolicyViolation => "policy violation",
            IdentityCoreError::InternalInvariant => "internal identity-core invariant violated",
        };
        f.write_str(msg)
    }
}

impl std::error::Error for IdentityCoreError {}

impl From<IdentityCoreError> for IdentityCoreErrorReason {
    fn from(error: IdentityCoreError) -> Self {
        match error {
            IdentityCoreError::InvalidCanonicalForm => {
                Self::IDENTITY_CORE_ERROR_REASON_CANONICALIZATION_FAILED
            }
            IdentityCoreError::AlgorithmNotAllowed => {
                Self::IDENTITY_CORE_ERROR_REASON_UNSUPPORTED_ALGORITHM
            }
            IdentityCoreError::PolicyViolation => Self::IDENTITY_CORE_ERROR_REASON_POLICY_VIOLATION,
            IdentityCoreError::InternalInvariant => Self::IDENTITY_CORE_ERROR_REASON_INVALID_STATE,
        }
    }
}
