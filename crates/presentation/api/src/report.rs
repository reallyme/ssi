// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::collections::BTreeSet;

use buffa::EnumValue;
use reallyme_disclosure_policy::VpPolicyError;
use reallyme_ssi_proto::generated::proto::identity::presentation::v1 as presentation_pb;
use reallyme_ssi_proto::generated::proto::reallyme::identity_core::v1::IdentityCoreErrorReason;
use thiserror::Error;

/// Proto conversion failures for VP verification report boundary values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum VpReportProtoError {
    /// The proto outcome was unspecified or unknown.
    #[error("unknown VP verification outcome")]
    UnknownOutcome,

    /// A proto failure class was unspecified or unknown.
    #[error("unknown VP failure class")]
    UnknownFailureClass,
}

impl From<VpReportProtoError> for IdentityCoreErrorReason {
    fn from(error: VpReportProtoError) -> Self {
        let _ = error;
        Self::IDENTITY_CORE_ERROR_REASON_INVALID_ENCODING
    }
}

/// Stable high-level failure classes for SDKs and delivery adapters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum VpFailureClass {
    /// Holder binding or audience binding failed.
    Binding,

    /// Accepted time window or freshness failed.
    Expired,

    /// Issuer or holder signing algorithm is outside policy.
    Algorithm,

    /// Presentation envelope format is outside policy.
    Format,

    /// Claimset or required-claim disclosure failed.
    Claims,

    /// A disclosed claim used an unacceptable disclosure mode.
    Disclosure,

    /// A predicate disclosure was present but did not satisfy policy.
    Predicate,

    /// Credential status was missing, stale, revoked, or suspended.
    Status,

    /// QEAA evidence was missing or below policy.
    Qeaa,

    /// Proof verification failed before policy evaluation.
    Proof,

    /// ZK derivation was required but no registered circuit could satisfy it.
    Zk,
}

impl From<VpFailureClass> for presentation_pb::VpFailureClass {
    fn from(class: VpFailureClass) -> Self {
        match class {
            VpFailureClass::Binding => Self::VP_FAILURE_CLASS_BINDING,
            VpFailureClass::Expired => Self::VP_FAILURE_CLASS_EXPIRED,
            VpFailureClass::Algorithm => Self::VP_FAILURE_CLASS_ALGORITHM,
            VpFailureClass::Format => Self::VP_FAILURE_CLASS_FORMAT,
            VpFailureClass::Claims => Self::VP_FAILURE_CLASS_CLAIMS,
            VpFailureClass::Disclosure => Self::VP_FAILURE_CLASS_DISCLOSURE,
            VpFailureClass::Predicate => Self::VP_FAILURE_CLASS_PREDICATE,
            VpFailureClass::Status => Self::VP_FAILURE_CLASS_STATUS,
            VpFailureClass::Qeaa => Self::VP_FAILURE_CLASS_QEAA,
            VpFailureClass::Proof => Self::VP_FAILURE_CLASS_PROOF,
            VpFailureClass::Zk => Self::VP_FAILURE_CLASS_ZK,
        }
    }
}

impl TryFrom<EnumValue<presentation_pb::VpFailureClass>> for VpFailureClass {
    type Error = VpReportProtoError;

    fn try_from(value: EnumValue<presentation_pb::VpFailureClass>) -> Result<Self, Self::Error> {
        match value.to_i32() {
            1 => Ok(Self::Binding),
            2 => Ok(Self::Expired),
            3 => Ok(Self::Algorithm),
            4 => Ok(Self::Format),
            5 => Ok(Self::Claims),
            6 => Ok(Self::Disclosure),
            7 => Ok(Self::Predicate),
            8 => Ok(Self::Status),
            9 => Ok(Self::Qeaa),
            10 => Ok(Self::Proof),
            11 => Ok(Self::Zk),
            _ => Err(VpReportProtoError::UnknownFailureClass),
        }
    }
}

/// Truth-first verification outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VpVerificationOutcome {
    /// The presentation satisfies policy.
    Accepted,

    /// The presentation failed policy.
    Rejected,
}

impl From<VpVerificationOutcome> for presentation_pb::VpVerificationOutcome {
    fn from(outcome: VpVerificationOutcome) -> Self {
        match outcome {
            VpVerificationOutcome::Accepted => Self::VP_VERIFICATION_OUTCOME_ACCEPTED,
            VpVerificationOutcome::Rejected => Self::VP_VERIFICATION_OUTCOME_REJECTED,
        }
    }
}

impl TryFrom<EnumValue<presentation_pb::VpVerificationOutcome>> for VpVerificationOutcome {
    type Error = VpReportProtoError;

    fn try_from(
        value: EnumValue<presentation_pb::VpVerificationOutcome>,
    ) -> Result<Self, Self::Error> {
        match value.to_i32() {
            1 => Ok(Self::Accepted),
            2 => Ok(Self::Rejected),
            _ => Err(VpReportProtoError::UnknownOutcome),
        }
    }
}

/// Verification report returned by the VP API.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VpVerificationReport {
    /// Overall decision.
    pub outcome: VpVerificationOutcome,

    /// Fixed, non-PII policy errors collected during evaluation.
    pub errors: Vec<VpPolicyError>,
}

impl VpVerificationReport {
    /// Build an accepted report.
    #[must_use]
    pub fn accepted() -> Self {
        Self {
            outcome: VpVerificationOutcome::Accepted,
            errors: Vec::new(),
        }
    }

    /// Build a rejected report with all collected failures.
    #[must_use]
    pub fn rejected(errors: Vec<VpPolicyError>) -> Self {
        Self {
            outcome: VpVerificationOutcome::Rejected,
            errors,
        }
    }

    /// Whether the presentation was accepted.
    #[must_use]
    pub fn is_accepted(&self) -> bool {
        self.outcome == VpVerificationOutcome::Accepted
    }

    /// Whether the presentation was rejected.
    #[must_use]
    pub fn is_rejected(&self) -> bool {
        self.outcome == VpVerificationOutcome::Rejected
    }

    /// Return stable high-level classes for the policy failures.
    #[must_use]
    pub fn failure_classes(&self) -> BTreeSet<VpFailureClass> {
        classify_failures(&self.errors)
    }

    /// Converts this report to the generated protobuf boundary summary.
    ///
    /// Detailed Rust policy errors intentionally do not cross the boundary.
    /// External callers receive the stable decision plus high-level classes.
    #[must_use]
    pub fn to_proto_summary(&self) -> presentation_pb::VpVerificationReport {
        presentation_pb::VpVerificationReport {
            outcome: EnumValue::from(presentation_pb::VpVerificationOutcome::from(self.outcome)),
            failure_classes: self
                .failure_classes()
                .into_iter()
                .map(presentation_pb::VpFailureClass::from)
                .map(EnumValue::from)
                .collect(),
            ..presentation_pb::VpVerificationReport::default()
        }
    }
}

/// Map fixed policy errors into stable failure classes.
#[must_use]
pub fn classify_failures(errors: &[VpPolicyError]) -> BTreeSet<VpFailureClass> {
    let mut classes = BTreeSet::new();

    for error in errors {
        let class = match error {
            VpPolicyError::InvalidBinding => VpFailureClass::Binding,
            VpPolicyError::Expired => VpFailureClass::Expired,
            VpPolicyError::AlgorithmNotAllowed => VpFailureClass::Algorithm,
            VpPolicyError::PresentationFormatNotAllowed => VpFailureClass::Format,
            VpPolicyError::ClaimsetNotAllowed
            | VpPolicyError::ClaimRegistryInvalid
            | VpPolicyError::RequiredClaimInvalid
            | VpPolicyError::MissingClaim => VpFailureClass::Claims,
            VpPolicyError::DisclosureModeNotAllowed | VpPolicyError::UnexpectedDisclosure => {
                VpFailureClass::Disclosure
            }
            VpPolicyError::PredicateNotSatisfied => VpFailureClass::Predicate,
            VpPolicyError::CredentialRevoked
            | VpPolicyError::CredentialSuspended
            | VpPolicyError::StatusCheckFailed
            | VpPolicyError::StatusTooOld => VpFailureClass::Status,
            VpPolicyError::QeaaLevelInsufficient
            | VpPolicyError::QeaaRequired
            | VpPolicyError::QeaaProfileMismatch => VpFailureClass::Qeaa,
            VpPolicyError::ProofInvalid => VpFailureClass::Proof,
            VpPolicyError::ZkDerivationUnavailable => VpFailureClass::Zk,
        };

        classes.insert(class);
    }

    classes
}

#[cfg(test)]
#[path = "report_proto_report_tests.rs"]
mod proto_report_tests;
