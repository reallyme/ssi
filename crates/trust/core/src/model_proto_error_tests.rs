// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{SignatureVerifyError, TrustFailureReason};
use reallyme_ssi_proto::generated::proto::reallyme::identity_core::v1::IdentityCoreErrorReason;

#[test]
fn trust_failure_reasons_map_to_stable_proto_reasons() {
    let cases = [
            (
                TrustFailureReason::NoValidPath,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TRUST_FAILURE_REASON_NO_VALID_PATH,
            ),
            (
                TrustFailureReason::ChainLinkPolicy,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TRUST_FAILURE_REASON_CHAIN_LINK_POLICY,
            ),
            (
                TrustFailureReason::Policy,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TRUST_FAILURE_REASON_POLICY,
            ),
            (
                TrustFailureReason::Status,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TRUST_FAILURE_REASON_STATUS,
            ),
            (
                TrustFailureReason::Signature,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TRUST_FAILURE_REASON_SIGNATURE,
            ),
            (
                TrustFailureReason::StatusRevoked,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TRUST_FAILURE_REASON_STATUS_REVOKED,
            ),
            (
                TrustFailureReason::StatusSuspended,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TRUST_FAILURE_REASON_STATUS_SUSPENDED,
            ),
            (
                TrustFailureReason::StatusUnknown,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TRUST_FAILURE_REASON_STATUS_UNKNOWN,
            ),
            (
                TrustFailureReason::StatusUnavailable,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TRUST_FAILURE_REASON_STATUS_UNAVAILABLE,
            ),
            (
                TrustFailureReason::StatusStale,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TRUST_FAILURE_REASON_STATUS_STALE,
            ),
            (
                TrustFailureReason::StatusNotYetValid,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TRUST_FAILURE_REASON_STATUS_NOT_YET_VALID,
            ),
            (
                TrustFailureReason::StatusMalformed,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TRUST_FAILURE_REASON_STATUS_MALFORMED,
            ),
            (
                TrustFailureReason::StatusInvalidSignature,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TRUST_FAILURE_REASON_STATUS_INVALID_SIGNATURE,
            ),
            (
                TrustFailureReason::StatusUnsupported,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TRUST_FAILURE_REASON_STATUS_UNSUPPORTED,
            ),
            (
                TrustFailureReason::SignatureIndeterminate,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TRUST_FAILURE_REASON_SIGNATURE_INDETERMINATE,
            ),
            (
                TrustFailureReason::InvalidEvaluationTime,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TRUST_INVALID_TIME,
            ),
            (
                TrustFailureReason::PathSearchLimit,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TRUST_FAILURE_REASON_PATH_SEARCH_LIMIT,
            ),
        ];

    for (reason, expected) in cases {
        assert_eq!(IdentityCoreErrorReason::from(reason), expected);
    }
}

#[test]
fn signature_verify_errors_map_to_stable_proto_reasons() {
    let cases = [
            (
                SignatureVerifyError::InvalidSignature,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TRUST_SIGNATURE_VERIFY_INVALID_SIGNATURE,
            ),
            (
                SignatureVerifyError::UnsupportedAlgorithm,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TRUST_SIGNATURE_VERIFY_UNSUPPORTED_ALGORITHM,
            ),
            (
                SignatureVerifyError::BackendFailure,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TRUST_SIGNATURE_VERIFY_BACKEND_FAILURE,
            ),
        ];

    for (error, expected) in cases {
        assert_eq!(IdentityCoreErrorReason::from(error), expected);
    }
}
