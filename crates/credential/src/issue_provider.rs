// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Host boundaries for credential issuance and authoritative lifecycle changes.

use reallyme_credential_claims::CredentialAlgorithm;

use crate::CredentialStatus;

/// Stable failures returned by an issuer-controlled signing provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum CredentialIssueProviderError {
    /// The provider does not offer credential signing.
    #[error("credential signing capability unsupported")]
    CapabilityUnsupported,

    /// The selected key or algorithm is forbidden by provider policy.
    #[error("credential signing policy rejected the request")]
    PolicyViolation,

    /// The provider failed without exposing backend or key material.
    #[error("credential signing provider failed")]
    ProviderFailure,

    /// The status source changed after the caller read it.
    #[error("credential lifecycle revision conflict")]
    RevisionConflict,
}

/// Credential state transition selected by the public operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialLifecycleAction {
    /// Temporarily prevent use of a credential.
    Suspend,
    /// Restore a previously suspended credential.
    Reactivate,
    /// Permanently prevent use of a credential.
    Revoke,
}

/// Privacy-safe reason category recorded with a lifecycle change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialLifecycleReason {
    /// The facts represented by the credential changed.
    InformationChanged,
    /// The credential should not have been issued.
    IssuedInError,
    /// The relationship or authorization represented by the credential ended.
    AccessEnded,
    /// A security event requires the credential to stop being accepted.
    SecurityEvent,
    /// A policy-defined reason that carries no free-form text.
    Other,
}

/// Validated provider input for one authoritative status transition.
pub struct CredentialLifecycleChange<'a> {
    /// Status-list entry named by the credential at issuance time.
    pub status: &'a CredentialStatus,
    /// Requested transition.
    pub action: CredentialLifecycleAction,
    /// Categorical reason suitable for privacy-safe audit records.
    pub reason: CredentialLifecycleReason,
    /// Effective time as Unix seconds.
    pub effective_at_unix: i64,
    /// Opaque retry key. Callers must not encode PII in this value.
    pub idempotency_key: &'a [u8; 16],
    /// Optional optimistic concurrency guard.
    pub expected_revision: Option<u64>,
}

/// Authoritative receipt returned after a lifecycle change is committed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CredentialLifecycleReceipt {
    /// State that is now authoritative.
    pub status: CredentialLifecycleStatus,
    /// Time at which the change applies.
    pub effective_at_unix: i64,
    /// Monotonic revision assigned by the status provider.
    pub revision: u64,
}

/// Credential state returned by a lifecycle provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialLifecycleStatus {
    /// The credential may be used.
    Active,
    /// Use is temporarily blocked.
    Suspended,
    /// Use is permanently blocked.
    Revoked,
}

/// Signs the exact canonical credential payload chosen by the SSI engine.
pub trait CredentialIssueProvider {
    /// Report whether direct credential signing is intentionally enabled.
    fn supports_credential_signing(&self) -> bool {
        false
    }

    /// Sign with the issuer key identified by a provider-owned reference.
    fn sign_credential(
        &self,
        _algorithm: CredentialAlgorithm,
        _provider_key_reference: &str,
        _payload: &[u8],
    ) -> Result<Vec<u8>, CredentialIssueProviderError> {
        Err(CredentialIssueProviderError::CapabilityUnsupported)
    }

    /// Report whether this provider can commit the selected lifecycle action.
    fn supports_credential_lifecycle(&self, _action: CredentialLifecycleAction) -> bool {
        false
    }

    /// Commit a status transition using provider-owned authorization and storage.
    fn change_credential_status(
        &self,
        _change: &CredentialLifecycleChange<'_>,
    ) -> Result<CredentialLifecycleReceipt, CredentialIssueProviderError> {
        Err(CredentialIssueProviderError::CapabilityUnsupported)
    }
}
