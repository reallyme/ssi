// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{ChainLinkPolicyViolation, TrustError, TrustResourceLimit};
use reallyme_ssi_proto::generated::proto::reallyme::identity_core::v1::IdentityCoreErrorReason;

#[test]
fn trust_errors_map_to_stable_proto_reasons() {
    let cases = [
            (
                TrustError::NoValidPath,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TRUST_NO_VALID_PATH,
            ),
            (
                TrustError::InvalidTime,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TRUST_INVALID_TIME,
            ),
            (
                TrustError::ChainLinkPolicy(
                    ChainLinkPolicyViolation::IssuerDistinguishedNameMismatch,
                ),
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TRUST_CHAIN_ISSUER_DISTINGUISHED_NAME_MISMATCH,
            ),
            (
                TrustError::InvalidSignature,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TRUST_INVALID_SIGNATURE,
            ),
            (
                TrustError::Revoked,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TRUST_REVOKED,
            ),
            (
                TrustError::StatusFailure,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TRUST_STATUS_FAILURE,
            ),
            (
                TrustError::Internal,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TRUST_INTERNAL,
            ),
            (
                TrustError::PurposePolicyMismatch,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TRUST_PURPOSE_POLICY_MISMATCH,
            ),
            (
                TrustError::ResourceLimit(TrustResourceLimit::TooManyTrustRoots),
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TRUST_RESOURCE_TOO_MANY_ROOTS,
            ),
            (
                TrustError::ResourceLimit(TrustResourceLimit::TooManyDirectTrustEntries),
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TRUST_RESOURCE_TOO_MANY_DIRECT_ENTRIES,
            ),
        ];

    for (error, expected) in cases {
        assert_eq!(IdentityCoreErrorReason::from(error), expected);
    }
}

#[test]
fn chain_link_policy_violations_map_to_stable_proto_reasons() {
    let cases = [
            (
                ChainLinkPolicyViolation::IssuerDistinguishedNameMismatch,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TRUST_CHAIN_ISSUER_DISTINGUISHED_NAME_MISMATCH,
            ),
            (
                ChainLinkPolicyViolation::AuthorityKeyIdentifierMismatch,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TRUST_CHAIN_AUTHORITY_KEY_IDENTIFIER_MISMATCH,
            ),
            (
                ChainLinkPolicyViolation::MissingAuthorityKeyIdentifier,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TRUST_CHAIN_MISSING_AUTHORITY_KEY_IDENTIFIER,
            ),
            (
                ChainLinkPolicyViolation::MissingSubjectKeyIdentifier,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TRUST_CHAIN_MISSING_SUBJECT_KEY_IDENTIFIER,
            ),
            (
                ChainLinkPolicyViolation::MissingKeyIdentifiers,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TRUST_CHAIN_MISSING_KEY_IDENTIFIERS,
            ),
        ];

    for (reason, expected) in cases {
        assert_eq!(IdentityCoreErrorReason::from(reason), expected);
    }
}
