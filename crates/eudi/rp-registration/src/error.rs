// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use thiserror::Error;

/// Closed, non-sensitive reasons an EUDI registration artifact is rejected.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegistrationErrorReason {
    /// Input was empty.
    EmptyInput,
    /// Input exceeded its profile bound.
    InputTooLarge,
    /// JSON syntax was invalid.
    InvalidJson,
    /// A JSON object repeated a member name.
    DuplicateJsonMember,
    /// A bounded collection, depth, or size was exceeded.
    ResourceLimitExceeded,
    /// A closed schema contained an unknown member.
    UnknownField,
    /// A mandatory profile field was absent.
    MissingField,
    /// A field value did not satisfy its type or profile.
    InvalidField,
    /// A URI was malformed or not admitted by policy.
    InvalidUri,
    /// A claim path was malformed or unbounded.
    InvalidClaimPath,
    /// The requested versioned profile is unsupported.
    UnsupportedProfile,
    /// The payload did not match the caller-selected shape.
    PayloadShapeMismatch,
    /// Compact JWS syntax or encoding was invalid.
    InvalidCompactJws,
    /// The cryptographic backend rejected the signature.
    SignatureVerificationFailed,
    /// A verifier receipt did not bind the submitted artifact.
    AuthenticationReceiptMismatch,
    /// The authenticated artifact omitted its signer certificate.
    MissingSignerCertificate,
    /// Certificate syntax was invalid.
    InvalidCertificate,
    /// Certificate fields violated the selected ETSI profile.
    CertificateProfileMismatch,
    /// Authenticated facts differed from the reviewed local binding.
    SemanticBindingMismatch,
    /// A validity interval was empty, inverted, or too long.
    InvalidValidityInterval,
    /// The evaluation time was outside the authenticated validity period.
    OutsideValidityPeriod,
    /// An authenticated response was older than the caller's freshness bound
    /// or was issued in the future beyond the permitted clock skew.
    ResponseNotFresh,
    /// A legacy response carried an answer without authenticated issuer,
    /// issue time, or query binding and cannot be relied upon.
    UnboundLegacyAnswer,
    /// Deterministic serialization failed.
    SerializationFailed,
    /// Memory capacity could not be reserved safely.
    CapacityUnavailable,
}

/// Audit-safe EUDI registration error.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum RegistrationError {
    /// The artifact was rejected for a stable validation reason.
    #[error("EUDI registration artifact validation failed")]
    Invalid(RegistrationErrorReason),
}

impl RegistrationError {
    pub(crate) const fn from_reason(reason: RegistrationErrorReason) -> Self {
        Self::Invalid(reason)
    }

    /// Returns the stable, non-sensitive reason.
    #[must_use]
    pub const fn reason(self) -> RegistrationErrorReason {
        match self {
            Self::Invalid(reason) => reason,
        }
    }
}
