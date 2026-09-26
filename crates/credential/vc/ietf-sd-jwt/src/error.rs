// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use thiserror::Error;

use reallyme_ssi_proto::generated::proto::reallyme::identity_core::v1::IdentityCoreErrorReason;

#[derive(Debug, Error)]
pub enum IetfSdJwtVcError {
    #[error("invalid input")]
    InvalidInput,

    #[error("missing JWT algorithm in JWK")]
    MissingAlgorithm,

    #[error("unsupported algorithm")]
    UnsupportedAlgorithm,

    #[error("signature error")]
    Signature,

    #[error("verification failed")]
    Verification,

    #[error("missing key binding proof")]
    MissingKeyBinding,

    #[error("serialization error")]
    Serialization,

    #[error("invalid compact SD-JWT format")]
    InvalidCompactFormat,

    #[error("invalid disclosure")]
    InvalidDisclosure,

    #[error("disclosure digest mismatch")]
    DisclosureDigestMismatch,

    #[error("duplicate claim key")]
    DuplicateClaimKey,

    #[error("reserved claim key")]
    ReservedClaimKey,

    #[error("invalid JWT header")]
    InvalidJwtHeader,

    #[error("missing _sd claim")]
    MissingSdClaim,

    #[error("_sd must contain unique digest strings")]
    InvalidSdClaim,

    #[error("invalid verification policy")]
    InvalidVerificationPolicy,

    #[error("invalid temporal claim")]
    InvalidTemporalClaim,

    #[error("credential has expired")]
    CredentialExpired,

    #[error("credential is not yet valid")]
    CredentialNotYetValid,

    #[error("SD-JWT processing limit exceeded")]
    ProcessingLimitExceeded,
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
            IetfSdJwtVcError::UnsupportedAlgorithm => {
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
            | IetfSdJwtVcError::ProcessingLimitExceeded => {
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
