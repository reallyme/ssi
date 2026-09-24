// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use thiserror::Error;

use reallyme_ssi_proto::generated::proto::reallyme::identity_core::v1::IdentityCoreErrorReason;

/// Current Data Integrity proof implementation status.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DataIntegrityProofStatus {
    /// At least one typed Data Integrity cryptosuite is active.
    Active,
}

/// Supported Data Integrity cryptosuites.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DataIntegrityCryptosuite {
    /// ReallyMe did:me proof over the current core CID.
    Es256JwsCid2025,
}

/// Error for Data Integrity proof operations.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum DataIntegrityProofError {
    /// Signing or verification input is structurally invalid.
    #[error("invalid Data Integrity proof input")]
    InvalidInput,

    /// The requested cryptosuite is not supported by this crate.
    #[error("unsupported Data Integrity cryptosuite")]
    UnsupportedCryptosuite,

    /// The selected cryptosuite rejected signing or verification.
    #[error("Data Integrity cryptosuite operation failed")]
    CryptosuiteFailed,
}

impl From<DataIntegrityProofError> for IdentityCoreErrorReason {
    fn from(reason: DataIntegrityProofError) -> Self {
        match reason {
            DataIntegrityProofError::InvalidInput => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_DATA_INTEGRITY_PROOF_INVALID_INPUT
            }
            DataIntegrityProofError::UnsupportedCryptosuite => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_DATA_INTEGRITY_PROOF_UNSUPPORTED_CRYPTOSUITE
            }
            DataIntegrityProofError::CryptosuiteFailed => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_DATA_INTEGRITY_PROOF_CRYPTOSUITE_FAILED
            }
        }
    }
}

/// Return the current Data Integrity proof implementation status.
pub const fn data_integrity_proof_status() -> DataIntegrityProofStatus {
    DataIntegrityProofStatus::Active
}

impl From<crate::suites::es256_jws_cid_2025::Es256JwsCid2025Error> for DataIntegrityProofError {
    fn from(_: crate::suites::es256_jws_cid_2025::Es256JwsCid2025Error) -> Self {
        DataIntegrityProofError::CryptosuiteFailed
    }
}

#[cfg(test)]
#[path = "proof_proto_error_tests.rs"]
mod proto_error_tests;
