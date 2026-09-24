// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use thiserror::Error;

use reallyme_ssi_proto::generated::proto::reallyme::identity_core::v1::IdentityCoreErrorReason;

/// Verification and signing failures for the `es256-jws-cid-2025` cryptosuite.
#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
pub enum Es256JwsCid2025Error {
    /// The DID document or signing inputs are structurally unusable.
    #[error("invalid input")]
    InvalidInput,

    /// The proof type is not `DataIntegrityProof`.
    #[error("unexpected proof type")]
    BadProofType,

    /// The proof cryptosuite is not `es256-jws-cid-2025`.
    #[error("unexpected cryptosuite")]
    BadCryptosuite,

    /// The proof does not identify a verification method.
    #[error("missing verification method")]
    MissingVerificationMethod,

    /// The proof does not contain a compact JWS.
    #[error("missing jws")]
    MissingJws,

    /// The verification method is not allowed for assertionMethod.
    #[error("verification method not allowed")]
    VerificationMethodNotAllowed,

    /// The referenced verification method is absent from the DID document.
    #[error("verification method not found")]
    VerificationMethodNotFound,

    /// The verification method public key cannot be decoded as a multikey.
    #[error("invalid multikey")]
    InvalidMultikey,

    /// The verification method is not a P-256 assertion key.
    #[error("wrong algorithm")]
    WrongAlgorithm,

    /// The compact JWS does not have the expected three-part form.
    #[error("malformed jws")]
    MalformedJws,

    /// The JWS protected header is not valid for this cryptosuite.
    #[error("bad jws header")]
    BadJwsHeader,

    /// The JWS payload does not match the DID document current core CID.
    #[error("payload mismatch")]
    PayloadMismatch,

    /// The JWS signature cannot be converted to the backend signature encoding.
    #[error("bad signature encoding")]
    BadSignatureEncoding,

    /// Signature verification failed.
    #[error("verification failed")]
    VerifyFailed,
}

impl From<Es256JwsCid2025Error> for IdentityCoreErrorReason {
    fn from(reason: Es256JwsCid2025Error) -> Self {
        match reason {
            Es256JwsCid2025Error::InvalidInput => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_ES256_JWS_CID_2025_INVALID_INPUT
            }
            Es256JwsCid2025Error::BadProofType => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_ES256_JWS_CID_2025_BAD_PROOF_TYPE
            }
            Es256JwsCid2025Error::BadCryptosuite => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_ES256_JWS_CID_2025_BAD_CRYPTOSUITE
            }
            Es256JwsCid2025Error::MissingVerificationMethod => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_ES256_JWS_CID_2025_MISSING_VERIFICATION_METHOD
            }
            Es256JwsCid2025Error::MissingJws => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_ES256_JWS_CID_2025_MISSING_JWS
            }
            Es256JwsCid2025Error::VerificationMethodNotAllowed => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_ES256_JWS_CID_2025_VERIFICATION_METHOD_NOT_ALLOWED
            }
            Es256JwsCid2025Error::VerificationMethodNotFound => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_ES256_JWS_CID_2025_VERIFICATION_METHOD_NOT_FOUND
            }
            Es256JwsCid2025Error::InvalidMultikey => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_ES256_JWS_CID_2025_INVALID_MULTIKEY
            }
            Es256JwsCid2025Error::WrongAlgorithm => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_ES256_JWS_CID_2025_WRONG_ALGORITHM
            }
            Es256JwsCid2025Error::MalformedJws => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_ES256_JWS_CID_2025_MALFORMED_JWS
            }
            Es256JwsCid2025Error::BadJwsHeader => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_ES256_JWS_CID_2025_BAD_JWS_HEADER
            }
            Es256JwsCid2025Error::PayloadMismatch => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_ES256_JWS_CID_2025_PAYLOAD_MISMATCH
            }
            Es256JwsCid2025Error::BadSignatureEncoding => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_ES256_JWS_CID_2025_BAD_SIGNATURE_ENCODING
            }
            Es256JwsCid2025Error::VerifyFailed => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_ES256_JWS_CID_2025_VERIFY_FAILED
            }
        }
    }
}

#[cfg(test)]
#[path = "error_proto_error_tests.rs"]
mod proto_error_tests;
