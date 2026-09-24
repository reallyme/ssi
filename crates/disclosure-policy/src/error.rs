// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_ssi_proto::generated::proto::reallyme::identity_core::v1::IdentityCoreErrorReason;
use thiserror::Error;

/// Fixed policy evaluation errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum VpPolicyError {
    /// Presentation holder binding was not validated or failed validation.
    #[error("presentation binding invalid")]
    InvalidBinding,

    /// Presentation freshness has expired.
    #[error("presentation expired")]
    Expired,

    /// Issuer or holder algorithm is outside policy.
    #[error("algorithm not allowed")]
    AlgorithmNotAllowed,

    /// Presentation format is outside policy.
    #[error("presentation format not allowed")]
    PresentationFormatNotAllowed,

    /// Credential claimset is outside policy.
    #[error("claimset not allowed")]
    ClaimsetNotAllowed,

    /// The claim registry failed semantic validation.
    #[error("claim registry invalid")]
    ClaimRegistryInvalid,

    /// A required claim path is invalid or absent from the registry.
    #[error("required claim invalid")]
    RequiredClaimInvalid,

    /// A required claim was not disclosed.
    #[error("required claim missing")]
    MissingClaim,

    /// The disclosure mode is not accepted for the required claim.
    #[error("disclosure mode not allowed")]
    DisclosureModeNotAllowed,

    /// Required predicate was not satisfied.
    #[error("predicate not satisfied")]
    PredicateNotSatisfied,

    /// Credential is revoked.
    #[error("credential revoked")]
    CredentialRevoked,

    /// Credential is suspended.
    #[error("credential suspended")]
    CredentialSuspended,

    /// Credential status was required and not successfully checked.
    #[error("status check failed")]
    StatusCheckFailed,

    /// Status information was too old for policy.
    #[error("status too old")]
    StatusTooOld,

    /// QEAA identity proofing level is below policy.
    #[error("QEAA identity proofing level insufficient")]
    QeaaLevelInsufficient,

    /// QEAA evidence was required and absent or not verified.
    #[error("QEAA compliance required but missing")]
    QeaaRequired,

    /// QEAA profile did not match policy.
    #[error("QEAA profile mismatch")]
    QeaaProfileMismatch,

    /// Proof verification failed before policy evaluation.
    #[error("proof verification failed")]
    ProofInvalid,

    /// Policy requires derived satisfaction but no registered circuit can satisfy it.
    #[error("zk derivation unavailable")]
    ZkDerivationUnavailable,
}

/// Policy evaluation decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyDecision {
    /// Presentation satisfies policy.
    Accept,

    /// Presentation fails policy with fixed, non-PII error categories.
    Reject(Vec<VpPolicyError>),
}

impl From<VpPolicyError> for IdentityCoreErrorReason {
    fn from(error: VpPolicyError) -> Self {
        match error {
            VpPolicyError::InvalidBinding | VpPolicyError::Expired => {
                Self::IDENTITY_CORE_ERROR_REASON_PRESENTATION_BINDING_FAILED
            }
            VpPolicyError::AlgorithmNotAllowed => {
                Self::IDENTITY_CORE_ERROR_REASON_UNSUPPORTED_ALGORITHM
            }
            VpPolicyError::PresentationFormatNotAllowed | VpPolicyError::ClaimsetNotAllowed => {
                Self::IDENTITY_CORE_ERROR_REASON_UNSUPPORTED_FORMAT
            }
            VpPolicyError::ClaimRegistryInvalid
            | VpPolicyError::RequiredClaimInvalid
            | VpPolicyError::MissingClaim
            | VpPolicyError::DisclosureModeNotAllowed
            | VpPolicyError::PredicateNotSatisfied => {
                Self::IDENTITY_CORE_ERROR_REASON_PRESENTATION_POLICY_NOT_SATISFIED
            }
            VpPolicyError::CredentialRevoked => {
                Self::IDENTITY_CORE_ERROR_REASON_CREDENTIAL_STATUS_REVOKED
            }
            VpPolicyError::CredentialSuspended => {
                Self::IDENTITY_CORE_ERROR_REASON_CREDENTIAL_STATUS_SUSPENDED
            }
            VpPolicyError::StatusCheckFailed | VpPolicyError::StatusTooOld => {
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
                .copied()
                .map(IdentityCoreErrorReason::from)
                .unwrap_or(Self::IDENTITY_CORE_ERROR_REASON_PRESENTATION_POLICY_NOT_SATISFIED),
        }
    }
}
