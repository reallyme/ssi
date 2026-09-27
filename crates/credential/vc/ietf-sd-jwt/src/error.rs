// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use thiserror::Error;

use reallyme_ssi_proto::generated::proto::reallyme::identity_core::v1::IdentityCoreErrorReason;

/// Typed failures returned by IETF SD-JWT VC operations.
#[derive(Debug, Error)]
pub enum IetfSdJwtVcError {
    /// The input violates the selected SD-JWT profile.
    #[error("invalid input")]
    InvalidInput,

    /// The signing JWK does not declare a JWT algorithm.
    #[error("missing JWT algorithm in JWK")]
    MissingAlgorithm,

    /// The declared algorithm is not supported by this profile.
    #[error("unsupported algorithm")]
    UnsupportedAlgorithm,

    /// The `_sd_alg` digest algorithm is not implemented by this profile.
    #[error("unsupported selective-disclosure hash algorithm")]
    UnsupportedHashAlgorithm,

    /// Signature creation or validation failed.
    #[error("signature error")]
    Signature,

    /// An authenticated value failed semantic verification.
    #[error("verification failed")]
    Verification,

    /// Holder binding is required, but no valid key-binding proof was supplied.
    #[error("missing key binding proof")]
    MissingKeyBinding,

    /// Serialization or deserialization failed.
    #[error("serialization error")]
    Serialization,

    /// The compact SD-JWT serialization is malformed.
    #[error("invalid compact SD-JWT format")]
    InvalidCompactFormat,

    /// A disclosure is malformed or violates the selected profile.
    #[error("invalid disclosure")]
    InvalidDisclosure,

    /// A disclosure does not match an issuer-signed digest.
    #[error("disclosure digest mismatch")]
    DisclosureDigestMismatch,

    /// A claim name appears more than once after disclosure processing.
    #[error("duplicate claim key")]
    DuplicateClaimKey,

    /// Application claims use a name reserved by SD-JWT.
    #[error("reserved claim key")]
    ReservedClaimKey,

    /// A JWT protected header is malformed or violates policy.
    #[error("invalid JWT header")]
    InvalidJwtHeader,

    /// A selectively disclosable payload does not contain `_sd`.
    #[error("missing _sd claim")]
    MissingSdClaim,

    /// The `_sd` claim contains a non-string or duplicate digest.
    #[error("_sd must contain unique digest strings")]
    InvalidSdClaim,

    /// Verification policy is internally inconsistent or exceeds supported bounds.
    #[error("invalid verification policy")]
    InvalidVerificationPolicy,

    /// A temporal claim is malformed or the claims form an invalid interval.
    #[error("invalid temporal claim")]
    InvalidTemporalClaim,

    /// The credential expired at or before the verification time.
    #[error("credential has expired")]
    CredentialExpired,

    /// The credential is not valid at the verification time.
    #[error("credential is not yet valid")]
    CredentialNotYetValid,

    /// Disclosure processing exceeded a configured resource limit.
    #[error("SD-JWT processing limit exceeded")]
    ProcessingLimitExceeded,

    /// A configured selective-disclosure path did not identify any claim.
    #[error("disclosure path did not match a claim")]
    DisclosurePathNotFound,
}

impl From<IetfSdJwtVcError> for IdentityCoreErrorReason {
    fn from(reason: IetfSdJwtVcError) -> Self {
        match reason {
            IetfSdJwtVcError::InvalidInput => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_IETF_SD_JWT_VC_INVALID_INPUT
            }
            IetfSdJwtVcError::MissingAlgorithm => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_IETF_SD_JWT_VC_MISSING_ALGORITHM
            }
            IetfSdJwtVcError::UnsupportedAlgorithm
            | IetfSdJwtVcError::UnsupportedHashAlgorithm => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_IETF_SD_JWT_VC_UNSUPPORTED_ALGORITHM
            }
            IetfSdJwtVcError::Signature => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_IETF_SD_JWT_VC_SIGNATURE
            }
            IetfSdJwtVcError::Verification => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_IETF_SD_JWT_VC_VERIFICATION
            }
            IetfSdJwtVcError::MissingKeyBinding => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_SD_JWT_HOLDER_BINDING_FAILED
            }
            IetfSdJwtVcError::Serialization => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_IETF_SD_JWT_VC_SERIALIZATION
            }
            IetfSdJwtVcError::InvalidCompactFormat => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_IETF_SD_JWT_VC_INVALID_COMPACT_FORMAT
            }
            IetfSdJwtVcError::InvalidDisclosure => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_IETF_SD_JWT_VC_INVALID_DISCLOSURE
            }
            IetfSdJwtVcError::DisclosureDigestMismatch => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_IETF_SD_JWT_VC_DISCLOSURE_DIGEST_MISMATCH
            }
            IetfSdJwtVcError::DuplicateClaimKey => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_IETF_SD_JWT_VC_DUPLICATE_CLAIM_KEY
            }
            IetfSdJwtVcError::ReservedClaimKey => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_IETF_SD_JWT_VC_RESERVED_CLAIM_KEY
            }
            IetfSdJwtVcError::InvalidJwtHeader => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_IETF_SD_JWT_VC_INVALID_JWT_HEADER
            }
            IetfSdJwtVcError::MissingSdClaim => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_IETF_SD_JWT_VC_MISSING_SD_CLAIM
            }
            IetfSdJwtVcError::InvalidSdClaim => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_IETF_SD_JWT_VC_INVALID_SD_CLAIM
            }
            IetfSdJwtVcError::InvalidVerificationPolicy
            | IetfSdJwtVcError::ProcessingLimitExceeded
            | IetfSdJwtVcError::DisclosurePathNotFound => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_IETF_SD_JWT_VC_INVALID_INPUT
            }
            IetfSdJwtVcError::InvalidTemporalClaim
            | IetfSdJwtVcError::CredentialExpired
            | IetfSdJwtVcError::CredentialNotYetValid => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_CREDENTIAL_INVALID_VALIDITY_WINDOW
            }
        }
    }
}

#[cfg(test)]
#[path = "error_proto_error_tests.rs"]
mod proto_error_tests;
