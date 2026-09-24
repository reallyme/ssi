// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_ssi_proto::generated::proto::reallyme::identity_core::v1::IdentityCoreErrorReason;
use thiserror::Error;

/// Trust protobuf conversion failures.
#[derive(Debug, Clone, Copy, Error, Eq, PartialEq)]
pub enum TrustProtoError {
    /// Protobuf trust decision failure value is unknown or unspecified.
    #[error("unknown trust decision failure")]
    UnknownDecisionFailure,
    /// Protobuf authorization purpose value is unknown or unspecified.
    #[error("unknown authorization purpose")]
    UnknownAuthorizationPurpose,
    /// Protobuf trust-decision outcome value is unknown or unspecified.
    #[error("unknown trust decision outcome")]
    UnknownDecisionOutcome,
    /// Protobuf trust-purpose value is unknown or unspecified.
    #[error("unknown trust purpose")]
    UnknownTrustPurpose,
    /// Protobuf trust-policy value is unknown or unspecified.
    #[error("unknown trust policy")]
    UnknownTrustPolicy,
    /// Protobuf trust-anchor kind is unknown or unspecified.
    #[error("unknown trust anchor kind")]
    UnknownTrustAnchorKind,
    /// Protobuf certificate-status value is unknown or unspecified.
    #[error("unknown certificate status")]
    UnknownCertificateStatus,
    /// Protobuf certificate-position value is unknown or inconsistent.
    #[error("unknown certificate position")]
    UnknownCertificatePosition,
    /// A newly required trust receipt field was absent or malformed.
    #[error("invalid trust decision evidence")]
    InvalidDecisionEvidence,
    /// Compatibility `accepted` and authoritative `outcome` fields disagree.
    #[error("inconsistent trust decision outcome")]
    InconsistentDecisionOutcome,
    /// Trust purpose and versioned policy identifier do not describe one profile.
    #[error("inconsistent trust purpose and policy")]
    InconsistentPurposePolicy,
    /// Repeated protobuf evidence exceeded the trust contract's fixed bounds.
    #[error("trust decision protobuf resource limit")]
    ResourceLimit,
}

impl From<TrustProtoError> for IdentityCoreErrorReason {
    fn from(error: TrustProtoError) -> Self {
        match error {
            TrustProtoError::UnknownDecisionFailure => {
                Self::IDENTITY_CORE_ERROR_REASON_TRUST_PROTO_UNKNOWN_DECISION_FAILURE
            }
            TrustProtoError::UnknownAuthorizationPurpose => {
                Self::IDENTITY_CORE_ERROR_REASON_TRUST_PROTO_UNKNOWN_AUTHORIZATION_PURPOSE
            }
            TrustProtoError::UnknownDecisionOutcome => {
                Self::IDENTITY_CORE_ERROR_REASON_TRUST_PROTO_UNKNOWN_DECISION_OUTCOME
            }
            TrustProtoError::UnknownTrustPurpose => {
                Self::IDENTITY_CORE_ERROR_REASON_TRUST_PROTO_UNKNOWN_TRUST_PURPOSE
            }
            TrustProtoError::UnknownTrustPolicy => {
                Self::IDENTITY_CORE_ERROR_REASON_TRUST_PROTO_UNKNOWN_TRUST_POLICY
            }
            TrustProtoError::UnknownTrustAnchorKind => {
                Self::IDENTITY_CORE_ERROR_REASON_TRUST_PROTO_UNKNOWN_TRUST_ANCHOR_KIND
            }
            TrustProtoError::UnknownCertificateStatus => {
                Self::IDENTITY_CORE_ERROR_REASON_TRUST_PROTO_UNKNOWN_CERTIFICATE_STATUS
            }
            TrustProtoError::UnknownCertificatePosition => {
                Self::IDENTITY_CORE_ERROR_REASON_TRUST_PROTO_UNKNOWN_CERTIFICATE_POSITION
            }
            TrustProtoError::InvalidDecisionEvidence => {
                Self::IDENTITY_CORE_ERROR_REASON_TRUST_PROTO_INVALID_DECISION_EVIDENCE
            }
            TrustProtoError::InconsistentDecisionOutcome => {
                Self::IDENTITY_CORE_ERROR_REASON_TRUST_PROTO_INCONSISTENT_DECISION_OUTCOME
            }
            TrustProtoError::InconsistentPurposePolicy => {
                Self::IDENTITY_CORE_ERROR_REASON_TRUST_PROTO_INCONSISTENT_PURPOSE_POLICY
            }
            TrustProtoError::ResourceLimit => {
                Self::IDENTITY_CORE_ERROR_REASON_TRUST_PROTO_RESOURCE_LIMIT
            }
        }
    }
}
