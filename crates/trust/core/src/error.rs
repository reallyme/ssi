// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use thiserror::Error;

use reallyme_ssi_proto::generated::proto::reallyme::identity_core::v1::IdentityCoreErrorReason;

/// Trust evaluation failures.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum TrustError {
    /// No acceptable path could be built to a configured trust anchor.
    #[error("no valid trust path found")]
    NoValidPath,

    /// Certificate validity windows do not include the evaluation time.
    #[error("certificate expired or not yet valid")]
    InvalidTime,

    /// Non-cryptographic chain-link policy failed.
    #[error("chain linkage policy violation")]
    ChainLinkPolicy(ChainLinkPolicyViolation),

    /// Signature verification failed.
    #[error("signature verification failed")]
    InvalidSignature,

    /// Revocation policy rejected the credential or certificate.
    #[error("revocation check failed")]
    Revoked,

    /// Status checking could not complete successfully.
    #[error("status check failed")]
    StatusFailure,

    /// Internal trust evaluation failure.
    #[error("internal error")]
    Internal,

    /// The authorization purpose and policy profile do not form a supported pair.
    #[error("trust purpose and policy mismatch")]
    PurposePolicyMismatch,

    /// Caller-supplied trust configuration exceeded a fixed resource bound.
    #[error("trust configuration resource limit exceeded")]
    ResourceLimit(TrustResourceLimit),
}

/// Fixed resource-limit classes enforced at the trust-core boundary.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum TrustResourceLimit {
    /// The configured PKIX root collection exceeded its fixed bound.
    #[error("too many configured trust roots")]
    TooManyTrustRoots,

    /// The purpose-scoped direct-trust collection exceeded its fixed bound.
    #[error("too many configured direct-trust entries")]
    TooManyDirectTrustEntries,
}

/// Non-cryptographic chain-link policy violations.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum ChainLinkPolicyViolation {
    /// Issuer and subject distinguished names do not chain.
    #[error("issuer distinguished name mismatch")]
    IssuerDistinguishedNameMismatch,

    /// Authority key identifier and subject key identifier do not match.
    #[error("authority key identifier mismatch")]
    AuthorityKeyIdentifierMismatch,

    /// Authority key identifier was required but absent.
    #[error("missing authority key identifier")]
    MissingAuthorityKeyIdentifier,

    /// Subject key identifier was required but absent.
    #[error("missing subject key identifier")]
    MissingSubjectKeyIdentifier,

    /// Key identifiers required for chain linking were absent.
    #[error("missing key identifiers")]
    MissingKeyIdentifiers,
}

impl From<ChainLinkPolicyViolation> for IdentityCoreErrorReason {
    fn from(reason: ChainLinkPolicyViolation) -> Self {
        match reason {
            ChainLinkPolicyViolation::IssuerDistinguishedNameMismatch => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TRUST_CHAIN_ISSUER_DISTINGUISHED_NAME_MISMATCH
            }
            ChainLinkPolicyViolation::AuthorityKeyIdentifierMismatch => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TRUST_CHAIN_AUTHORITY_KEY_IDENTIFIER_MISMATCH
            }
            ChainLinkPolicyViolation::MissingAuthorityKeyIdentifier => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TRUST_CHAIN_MISSING_AUTHORITY_KEY_IDENTIFIER
            }
            ChainLinkPolicyViolation::MissingSubjectKeyIdentifier => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TRUST_CHAIN_MISSING_SUBJECT_KEY_IDENTIFIER
            }
            ChainLinkPolicyViolation::MissingKeyIdentifiers => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TRUST_CHAIN_MISSING_KEY_IDENTIFIERS
            }
        }
    }
}

impl From<TrustError> for IdentityCoreErrorReason {
    fn from(reason: TrustError) -> Self {
        match reason {
            TrustError::NoValidPath => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TRUST_NO_VALID_PATH
            }
            TrustError::InvalidTime => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TRUST_INVALID_TIME
            }
            TrustError::ChainLinkPolicy(reason) => reason.into(),
            TrustError::InvalidSignature => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TRUST_INVALID_SIGNATURE
            }
            TrustError::Revoked => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TRUST_REVOKED
            }
            TrustError::StatusFailure => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TRUST_STATUS_FAILURE
            }
            TrustError::Internal => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TRUST_INTERNAL
            }
            TrustError::PurposePolicyMismatch => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TRUST_PURPOSE_POLICY_MISMATCH
            }
            TrustError::ResourceLimit(TrustResourceLimit::TooManyTrustRoots) => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TRUST_RESOURCE_TOO_MANY_ROOTS
            }
            TrustError::ResourceLimit(TrustResourceLimit::TooManyDirectTrustEntries) => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TRUST_RESOURCE_TOO_MANY_DIRECT_ENTRIES
            }
        }
    }
}

#[cfg(test)]
#[path = "error_proto_error_tests.rs"]
mod proto_error_tests;
