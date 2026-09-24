// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_ssi_proto::generated::proto::reallyme::identity_core::v1::IdentityCoreErrorReason;
use thiserror::Error;

/// Stable reason returned by a compact-JWS cryptographic backend.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompactJwsVerificationErrorReason {
    /// Compact input or its authenticated encoding is invalid.
    InvalidInput,
    /// The selected signature algorithm is not implemented by the backend.
    UnsupportedAlgorithm,
    /// Cryptographic signature verification failed.
    InvalidSignature,
    /// Verification could not complete without exposing backend details.
    BackendFailure,
}

/// Typed, non-sensitive compact-JWS backend error.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("compact JWS verification failed")]
pub struct CompactJwsVerificationError {
    reason: CompactJwsVerificationErrorReason,
}

impl CompactJwsVerificationError {
    /// Creates a backend error from its stable reason.
    #[must_use]
    pub const fn new(reason: CompactJwsVerificationErrorReason) -> Self {
        Self { reason }
    }

    /// Returns the stable reason without backend text or input material.
    #[must_use]
    pub const fn reason(self) -> CompactJwsVerificationErrorReason {
        self.reason
    }
}

/// Stable JAdES validation failure reason.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JadesErrorReason {
    /// Compact JWS structure or size is invalid.
    InvalidCompactSerialization,
    /// Protected header JSON or its encoding is invalid.
    InvalidProtectedHeader,
    /// The protected signature algorithm is not admitted or implemented.
    UnsupportedSignatureAlgorithm,
    /// The compact signature failed authentication.
    InvalidSignature,
    /// Neither `iat` nor legacy `sigT` is protected.
    MissingClaimedSigningTime,
    /// A claimed signing time is ambiguous or malformed.
    InvalidClaimedSigningTime,
    /// The claimed time violates transition, skew, or certificate validity policy.
    SigningTimeOutsidePolicy,
    /// No protected signing-certificate identifier is present.
    MissingSigningCertificateReference,
    /// A protected certificate-reference structure or encoding is invalid.
    InvalidCertificateReference,
    /// A certificate-reference digest algorithm is not admitted.
    UnsupportedDigestAlgorithm,
    /// A protected certificate identifier does not match the signing chain.
    SigningCertificateMismatch,
    /// The signing certificate or its key is malformed or incompatible.
    InvalidSigningCertificate,
    /// X.509 path or status policy conclusively rejected the signer.
    CertificatePathRejected,
    /// Required X.509 path or status evidence was unavailable.
    CertificatePathIndeterminate,
    /// An input exceeded a deterministic resource bound.
    ResourceLimit,
}

/// Typed, allocation-free JAdES validation error.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("JAdES validation failed")]
pub struct JadesError {
    reason: JadesErrorReason,
}

impl JadesError {
    /// Creates an error from its stable, non-sensitive reason.
    #[must_use]
    pub const fn new(reason: JadesErrorReason) -> Self {
        Self { reason }
    }

    /// Returns the stable reason.
    #[must_use]
    pub const fn reason(self) -> JadesErrorReason {
        self.reason
    }
}

impl From<JadesErrorReason> for IdentityCoreErrorReason {
    fn from(reason: JadesErrorReason) -> Self {
        match reason {
            JadesErrorReason::InvalidCompactSerialization => {
                Self::IDENTITY_CORE_ERROR_REASON_JADES_INVALID_COMPACT_SERIALIZATION
            }
            JadesErrorReason::InvalidProtectedHeader => {
                Self::IDENTITY_CORE_ERROR_REASON_JADES_INVALID_PROTECTED_HEADER
            }
            JadesErrorReason::UnsupportedSignatureAlgorithm => {
                Self::IDENTITY_CORE_ERROR_REASON_JADES_UNSUPPORTED_SIGNATURE_ALGORITHM
            }
            JadesErrorReason::InvalidSignature => {
                Self::IDENTITY_CORE_ERROR_REASON_JADES_INVALID_SIGNATURE
            }
            JadesErrorReason::MissingClaimedSigningTime => {
                Self::IDENTITY_CORE_ERROR_REASON_JADES_MISSING_CLAIMED_SIGNING_TIME
            }
            JadesErrorReason::InvalidClaimedSigningTime => {
                Self::IDENTITY_CORE_ERROR_REASON_JADES_INVALID_CLAIMED_SIGNING_TIME
            }
            JadesErrorReason::SigningTimeOutsidePolicy => {
                Self::IDENTITY_CORE_ERROR_REASON_JADES_SIGNING_TIME_OUTSIDE_POLICY
            }
            JadesErrorReason::MissingSigningCertificateReference => {
                Self::IDENTITY_CORE_ERROR_REASON_JADES_MISSING_SIGNING_CERTIFICATE_REFERENCE
            }
            JadesErrorReason::InvalidCertificateReference => {
                Self::IDENTITY_CORE_ERROR_REASON_JADES_INVALID_CERTIFICATE_REFERENCE
            }
            JadesErrorReason::UnsupportedDigestAlgorithm => {
                Self::IDENTITY_CORE_ERROR_REASON_JADES_UNSUPPORTED_DIGEST_ALGORITHM
            }
            JadesErrorReason::SigningCertificateMismatch => {
                Self::IDENTITY_CORE_ERROR_REASON_JADES_SIGNING_CERTIFICATE_MISMATCH
            }
            JadesErrorReason::InvalidSigningCertificate => {
                Self::IDENTITY_CORE_ERROR_REASON_JADES_INVALID_SIGNING_CERTIFICATE
            }
            JadesErrorReason::CertificatePathRejected => {
                Self::IDENTITY_CORE_ERROR_REASON_JADES_CERTIFICATE_PATH_REJECTED
            }
            JadesErrorReason::CertificatePathIndeterminate => {
                Self::IDENTITY_CORE_ERROR_REASON_JADES_CERTIFICATE_PATH_INDETERMINATE
            }
            JadesErrorReason::ResourceLimit => {
                Self::IDENTITY_CORE_ERROR_REASON_JADES_RESOURCE_LIMIT
            }
        }
    }
}
