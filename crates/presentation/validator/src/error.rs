// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use identity_presentation_vp_policy::VpPolicyError;
use reallyme_ssi_proto::generated::proto::reallyme::identity_core::v1::IdentityCoreErrorReason;
use thiserror::Error;

/// Typed VP validation errors.
#[derive(Debug, Error)]
pub enum VpValidationError {
    /// The claimset is not supported by the selected verifier policy.
    #[error("unsupported claimset")]
    UnsupportedClaimset,

    /// Presentation binding failed or was not supplied.
    #[error("invalid binding")]
    InvalidBinding,

    /// Credential status checking failed.
    #[error("credential status check failed")]
    StatusCheckFailed,

    /// QEAA evidence was required but missing or invalid.
    #[error("QEAA compliance required")]
    QeaaRequired,

    /// A credential envelope was required for proof verification.
    #[error("missing credential envelope")]
    MissingCredentialEnvelope,

    /// Policy evaluation rejected the presentation.
    #[error("presentation rejected by policy")]
    PolicyRejected(Vec<VpPolicyError>),
}

impl From<&VpValidationError> for IdentityCoreErrorReason {
    fn from(error: &VpValidationError) -> Self {
        match error {
            VpValidationError::UnsupportedClaimset => {
                Self::IDENTITY_CORE_ERROR_REASON_UNSUPPORTED_FORMAT
            }
            VpValidationError::InvalidBinding => {
                Self::IDENTITY_CORE_ERROR_REASON_PRESENTATION_BINDING_FAILED
            }
            VpValidationError::StatusCheckFailed => {
                Self::IDENTITY_CORE_ERROR_REASON_CREDENTIAL_STATUS_CHECK_FAILED
            }
            VpValidationError::QeaaRequired => {
                Self::IDENTITY_CORE_ERROR_REASON_AUDIT_EVIDENCE_INVALID
            }
            VpValidationError::MissingCredentialEnvelope => {
                Self::IDENTITY_CORE_ERROR_REASON_CREDENTIAL_INVALID_ENVELOPE
            }
            VpValidationError::PolicyRejected(_) => {
                Self::IDENTITY_CORE_ERROR_REASON_PRESENTATION_POLICY_NOT_SATISFIED
            }
        }
    }
}
