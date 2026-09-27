// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0
use thiserror::Error;

use reallyme_ssi_proto::generated::proto::reallyme::identity_core::v1::IdentityCoreErrorReason;

/// Typed failures returned by committed-credential operations.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum VcError {
    /// Canonical CBOR encoding failed.
    #[error("canonicalization failed")]
    Canonicalization,

    /// Invalid credential model.
    #[error("invalid credential")]
    InvalidCredential,

    /// Unsupported or inconsistent credential profile.
    #[error("unsupported credential profile")]
    UnsupportedProfile,

    /// Proof material does not describe the credential and holder bundle with
    /// which it was presented.
    #[error("credential proof binding mismatch")]
    ProofBindingMismatch,

    /// The issuer key embedded in the credential does not match the key
    /// selected by the caller's trust decision.
    #[error("credential proof binding issuer mismatch")]
    ProofBindingTrustedIssuerMismatch,

    /// An issuer signature authenticating proof-binding material is invalid.
    #[error("credential proof binding signature invalid")]
    ProofBindingSignatureInvalid,

    /// Credential issuance could not obtain acceptable entropy.
    ///
    /// The public message deliberately does not distinguish an unavailable
    /// system RNG from repeated invalid output, because backend details must
    /// not cross the credential boundary.
    #[error("credential issuance failed")]
    EntropyUnavailable,
}

impl From<VcError> for IdentityCoreErrorReason {
    fn from(reason: VcError) -> Self {
        match reason {
            VcError::Canonicalization => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_VC_CANONICALIZATION
            }
            VcError::InvalidCredential => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_VC_INVALID_CREDENTIAL
            }
            VcError::UnsupportedProfile => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_VC_UNSUPPORTED_PROFILE
            }
            VcError::ProofBindingMismatch => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_VC_PROOF_BINDING_MISMATCH
            }
            VcError::ProofBindingTrustedIssuerMismatch => IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_VC_PROOF_BINDING_TRUSTED_ISSUER_MISMATCH,
            VcError::ProofBindingSignatureInvalid => IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_VC_PROOF_BINDING_SIGNATURE_INVALID,
            VcError::EntropyUnavailable => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_VC_API_ISSUANCE_FAILED
            }
        }
    }
}

#[cfg(test)]
#[path = "error_proto_error_tests.rs"]
mod proto_error_tests;
