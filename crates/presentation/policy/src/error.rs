// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_ssi_proto::generated::proto::reallyme::identity_core::v1::IdentityCoreErrorReason;
use thiserror::Error;

/// Fixed policy-evaluation failures.
///
/// Variants intentionally carry no claim paths or raw values so the error surface
/// remains deterministic and safe for SDKs, logs, and FFI mappings.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum VpPolicyError {
    /// Holder binding, audience binding, or equivalent freshness binding failed.
    #[error("presentation binding invalid")]
    InvalidBinding,

    /// Presentation freshness has expired.
    #[error("presentation expired")]
    Expired,

    /// Issuer or holder algorithm is outside verifier policy.
    #[error("algorithm not allowed")]
    AlgorithmNotAllowed,

    /// Presentation format is outside verifier policy.
    #[error("presentation format not allowed")]
    PresentationFormatNotAllowed,

    /// A required claim was absent or not disclosed.
    #[error("required claim missing")]
    MissingClaim,

    /// The configured verifier policy is internally inconsistent.
    #[error("policy misconfiguration")]
    PolicyMisconfiguration,

    /// The holder used a disclosure mode disallowed by the claim registry.
    #[error("disclosure not allowed for claim")]
    DisclosureNotAllowed,

    /// A required predicate was absent or not satisfied.
    #[error("predicate not satisfied for claim")]
    PredicateNotSatisfied,

    /// Credential status indicates revocation.
    #[error("credential revoked")]
    CredentialRevoked,

    /// Credential status indicates suspension.
    #[error("credential suspended")]
    CredentialSuspended,

    /// Status information could not be checked successfully.
    #[error("status check failed")]
    StatusCheckFailed,

    /// QEAA identity proofing level is below policy.
    #[error("QEAA identity proofing level insufficient")]
    QeaaLevelInsufficient,

    /// QEAA evidence was required but missing or not validated.
    #[error("QEAA compliance required but missing")]
    QeaaRequired,

    /// QEAA profile identifier did not match policy.
    #[error("QEAA profile mismatch")]
    QeaaProfileMismatch,

    /// Presentation proof verification failed before policy could accept it.
    #[error("proof verification failed")]
    ProofInvalid,

    /// Required ZK derivation cannot be produced by registered capabilities.
    #[error("zk derivation unavailable")]
    ZkDerivationUnavailable,
}

/// Policy evaluation outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyDecision {
    /// Presentation satisfies the verifier policy.
    Accept,

    /// Presentation failed policy with fixed failure categories.
    Reject(Vec<VpPolicyError>),
}

impl From<&VpPolicyError> for IdentityCoreErrorReason {
    fn from(error: &VpPolicyError) -> Self {
        match error {
            VpPolicyError::InvalidBinding | VpPolicyError::Expired => {
                Self::IDENTITY_CORE_ERROR_REASON_PRESENTATION_BINDING_FAILED
            }
            VpPolicyError::AlgorithmNotAllowed => {
                Self::IDENTITY_CORE_ERROR_REASON_UNSUPPORTED_ALGORITHM
            }
            VpPolicyError::PresentationFormatNotAllowed => {
                Self::IDENTITY_CORE_ERROR_REASON_UNSUPPORTED_FORMAT
            }
            VpPolicyError::MissingClaim
            | VpPolicyError::DisclosureNotAllowed
            | VpPolicyError::PredicateNotSatisfied => {
                Self::IDENTITY_CORE_ERROR_REASON_PRESENTATION_POLICY_NOT_SATISFIED
            }
            VpPolicyError::PolicyMisconfiguration => {
                Self::IDENTITY_CORE_ERROR_REASON_POLICY_VIOLATION
            }
            VpPolicyError::CredentialRevoked => {
                Self::IDENTITY_CORE_ERROR_REASON_CREDENTIAL_STATUS_REVOKED
            }
            VpPolicyError::CredentialSuspended => {
                Self::IDENTITY_CORE_ERROR_REASON_CREDENTIAL_STATUS_SUSPENDED
            }
            VpPolicyError::StatusCheckFailed => {
                Self::IDENTITY_CORE_ERROR_REASON_CREDENTIAL_STATUS_CHECK_FAILED
            }
            VpPolicyError::QeaaLevelInsufficient
            | VpPolicyError::QeaaRequired
            | VpPolicyError::QeaaProfileMismatch => {
                Self::IDENTITY_CORE_ERROR_REASON_AUDIT_EVIDENCE_INVALID
            }
            VpPolicyError::ProofInvalid => Self::IDENTITY_CORE_ERROR_REASON_INVALID_PROOF,
            VpPolicyError::ZkDerivationUnavailable => {
                Self::IDENTITY_CORE_ERROR_REASON_ZK_UNSUPPORTED_CIRCUIT
            }
        }
    }
}

impl From<&PolicyDecision> for IdentityCoreErrorReason {
    fn from(decision: &PolicyDecision) -> Self {
        match decision {
            PolicyDecision::Accept => Self::IDENTITY_CORE_ERROR_REASON_UNSPECIFIED,
            PolicyDecision::Reject(reasons) => reasons
                .first()
                .map(IdentityCoreErrorReason::from)
                .unwrap_or(Self::IDENTITY_CORE_ERROR_REASON_PRESENTATION_POLICY_NOT_SATISFIED),
        }
    }
}
