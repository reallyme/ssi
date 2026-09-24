// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_ssi_proto::generated::proto::reallyme::identity_core::v1::IdentityCoreErrorReason;

impl From<TrustFailureReason> for IdentityCoreErrorReason {
    fn from(reason: TrustFailureReason) -> Self {
        match reason {
            TrustFailureReason::NoValidPath => {
                Self::IDENTITY_CORE_ERROR_REASON_TRUST_FAILURE_REASON_NO_VALID_PATH
            }
            TrustFailureReason::ChainLinkPolicy => {
                Self::IDENTITY_CORE_ERROR_REASON_TRUST_FAILURE_REASON_CHAIN_LINK_POLICY
            }
            TrustFailureReason::Policy => {
                Self::IDENTITY_CORE_ERROR_REASON_TRUST_FAILURE_REASON_POLICY
            }
            TrustFailureReason::Status => {
                Self::IDENTITY_CORE_ERROR_REASON_TRUST_FAILURE_REASON_STATUS
            }
            TrustFailureReason::StatusRevoked => {
                Self::IDENTITY_CORE_ERROR_REASON_TRUST_FAILURE_REASON_STATUS_REVOKED
            }
            TrustFailureReason::StatusSuspended => {
                Self::IDENTITY_CORE_ERROR_REASON_TRUST_FAILURE_REASON_STATUS_SUSPENDED
            }
            TrustFailureReason::StatusUnknown => {
                Self::IDENTITY_CORE_ERROR_REASON_TRUST_FAILURE_REASON_STATUS_UNKNOWN
            }
            TrustFailureReason::StatusUnavailable => {
                Self::IDENTITY_CORE_ERROR_REASON_TRUST_FAILURE_REASON_STATUS_UNAVAILABLE
            }
            TrustFailureReason::StatusStale => {
                Self::IDENTITY_CORE_ERROR_REASON_TRUST_FAILURE_REASON_STATUS_STALE
            }
            TrustFailureReason::StatusNotYetValid => {
                Self::IDENTITY_CORE_ERROR_REASON_TRUST_FAILURE_REASON_STATUS_NOT_YET_VALID
            }
            TrustFailureReason::StatusMalformed => {
                Self::IDENTITY_CORE_ERROR_REASON_TRUST_FAILURE_REASON_STATUS_MALFORMED
            }
            TrustFailureReason::StatusInvalidSignature => {
                Self::IDENTITY_CORE_ERROR_REASON_TRUST_FAILURE_REASON_STATUS_INVALID_SIGNATURE
            }
            TrustFailureReason::StatusUnsupported => {
                Self::IDENTITY_CORE_ERROR_REASON_TRUST_FAILURE_REASON_STATUS_UNSUPPORTED
            }
            TrustFailureReason::Signature => {
                Self::IDENTITY_CORE_ERROR_REASON_TRUST_FAILURE_REASON_SIGNATURE
            }
            TrustFailureReason::SignatureIndeterminate => {
                Self::IDENTITY_CORE_ERROR_REASON_TRUST_FAILURE_REASON_SIGNATURE_INDETERMINATE
            }
            TrustFailureReason::InvalidEvaluationTime => {
                Self::IDENTITY_CORE_ERROR_REASON_TRUST_INVALID_TIME
            }
            TrustFailureReason::PathSearchLimit => {
                Self::IDENTITY_CORE_ERROR_REASON_TRUST_FAILURE_REASON_PATH_SEARCH_LIMIT
            }
        }
    }
}

impl From<SignatureVerifyError> for IdentityCoreErrorReason {
    fn from(reason: SignatureVerifyError) -> Self {
        match reason {
            SignatureVerifyError::InvalidSignature => {
                Self::IDENTITY_CORE_ERROR_REASON_TRUST_SIGNATURE_VERIFY_INVALID_SIGNATURE
            }
            SignatureVerifyError::UnsupportedAlgorithm => {
                Self::IDENTITY_CORE_ERROR_REASON_TRUST_SIGNATURE_VERIFY_UNSUPPORTED_ALGORITHM
            }
            SignatureVerifyError::BackendFailure => {
                Self::IDENTITY_CORE_ERROR_REASON_TRUST_SIGNATURE_VERIFY_BACKEND_FAILURE
            }
        }
    }
}
