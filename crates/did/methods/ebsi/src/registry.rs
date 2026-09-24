// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Pure authenticated-write boundary for the EBSI DID Registry.
//!
//! OAuth, access-token acquisition, transaction signing, HTTP, JSON-RPC, and
//! receipt polling belong to adapters. This module validates the public state
//! transition before and after the injected adapter is invoked.

use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::registry_transition::validate_transition;
use crate::{
    parse_and_validate_did_ebsi_document, parse_and_validate_did_ebsi_document_for_state,
    DidEbsiDocument, DidEbsiDocumentLimits, DidEbsiDocumentState, DidEbsiError, DidEbsiErrorReason,
};

const MAX_REGISTRY_METADATA_BYTES: usize = 1024;

/// Closed write operations supported by the legal-entity registry profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DidEbsiRegistryOperation {
    /// Insert the initial legal-entity document.
    RegisterDocument,
    /// Update non-authority base-document properties such as services.
    UpdateDocument,
    /// Add one legal-entity controller.
    AddController,
    /// Revoke one legal-entity controller.
    RevokeController,
    /// Add one public verification method.
    AddVerificationMethod,
    /// Add one reference to a verification relationship.
    AddVerificationRelationship,
    /// Revoke one verification relationship reference.
    RevokeVerificationRelationship,
    /// Replace public material for one stable verification-method id.
    RotateVerificationMethod,
    /// Expire one verification method at an explicit instant.
    ExpireVerificationMethod,
    /// Revoke one verification method at an explicit instant.
    RevokeVerificationMethod,
    /// Clear controllers or invocation authority to make the DID immutable.
    DeactivateKeys,
}

/// Stable provider failures that never carry access tokens or registry text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DidEbsiRegistryProviderErrorReason {
    /// The configured registry endpoint or adapter is unavailable.
    Unavailable,
    /// Authentication was absent, expired, or rejected.
    Unauthenticated,
    /// The registry authorization policy rejected the operation.
    Unauthorized,
    /// Transport failed without exposing request or response material.
    Transport,
    /// The registry rejected the signed operation.
    RegistryRejected,
    /// The operation exceeded its deadline.
    Timeout,
    /// The caller cancelled the operation.
    Cancelled,
}

/// Privacy-safe error returned by an injected registry adapter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("did:ebsi registry provider failure")]
pub struct DidEbsiRegistryProviderError {
    /// Stable provider failure reason.
    pub reason: DidEbsiRegistryProviderErrorReason,
}

/// Borrowed registry mutation passed to an authenticated adapter.
pub struct DidEbsiRegistryWriteRequest<'a> {
    /// Exact operation the adapter must execute.
    pub operation: DidEbsiRegistryOperation,
    /// Canonical legal-entity DID.
    pub did: &'a str,
    /// Previously active registry document, absent only for registration.
    pub current_document: Option<&'a DidEbsiDocument>,
    /// Fully validated proposed registry state.
    pub proposed_document: &'a DidEbsiDocument,
    /// Current capabilityInvocation method authorizing the mutation.
    pub authorization_method: &'a str,
    /// Verification method or controller affected by a focused mutation.
    pub target: Option<&'a str>,
    /// RFC 3339 time for expiration, revocation, rotation, or deactivation.
    pub effective_at: Option<&'a str>,
}

/// Adapter response awaiting exact operation and document correlation checks.
pub struct DidEbsiRegistryWriteResponse {
    /// Operation the registry confirms it applied.
    pub operation: DidEbsiRegistryOperation,
    /// Stable opaque registry version identifier.
    pub version_id: String,
    /// Monotonic registry version sequence.
    pub version_sequence: u64,
    /// RFC 3339 inclusive start of the new document version.
    pub valid_from: String,
    /// Registry-returned public document bytes.
    pub document_json: Vec<u8>,
}

impl core::fmt::Debug for DidEbsiRegistryWriteResponse {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("DidEbsiRegistryWriteResponse(<redacted>)")
    }
}

impl Zeroize for DidEbsiRegistryWriteResponse {
    fn zeroize(&mut self) {
        self.version_id.zeroize();
        self.version_sequence = 0;
        self.valid_from.zeroize();
        self.document_json.zeroize();
        self.document_json.clear();
    }
}

impl Drop for DidEbsiRegistryWriteResponse {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for DidEbsiRegistryWriteResponse {}

/// Injected authenticated EBSI DID Registry write adapter.
pub trait AuthenticatedDidEbsiRegistryProvider {
    /// Report whether current authentication covers the exact operation class.
    fn is_authenticated_for(&self, operation: DidEbsiRegistryOperation) -> bool;

    /// Execute an already validated mutation.
    fn execute(
        &self,
        request: DidEbsiRegistryWriteRequest<'_>,
    ) -> Result<DidEbsiRegistryWriteResponse, DidEbsiRegistryProviderError>;
}

/// Validated registry state and correlation metadata returned to orchestration.
pub struct DidEbsiRegistryWriteResult {
    /// Registry-confirmed public document.
    pub document: DidEbsiDocument,
    /// Opaque registry version identifier.
    pub version_id: String,
    /// Monotonic registry version sequence.
    pub version_sequence: u64,
    /// Inclusive RFC 3339 start of this document version.
    pub valid_from: String,
}

impl core::fmt::Debug for DidEbsiRegistryWriteResult {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("DidEbsiRegistryWriteResult(<redacted>)")
    }
}

impl Zeroize for DidEbsiRegistryWriteResult {
    fn zeroize(&mut self) {
        self.document.zeroize();
        self.version_id.zeroize();
        self.version_sequence = 0;
        self.valid_from.zeroize();
    }
}

impl Drop for DidEbsiRegistryWriteResult {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for DidEbsiRegistryWriteResult {}

/// Build and validate a local active legal-entity document without I/O.
pub fn create_did_ebsi_document(
    did: &str,
    document_json: &[u8],
    limits: DidEbsiDocumentLimits,
) -> Result<DidEbsiDocument, DidEbsiError> {
    parse_and_validate_did_ebsi_document(did, document_json, limits)
}

/// Validate, authorize, execute, and correlate one registry write.
#[allow(clippy::too_many_arguments)]
pub fn write_did_ebsi_registry_document(
    provider: Option<&dyn AuthenticatedDidEbsiRegistryProvider>,
    operation: DidEbsiRegistryOperation,
    did: &str,
    current_document_json: Option<&[u8]>,
    proposed_document_json: &[u8],
    authorization_method: &str,
    target: Option<&str>,
    effective_at: Option<&str>,
    limits: DidEbsiDocumentLimits,
) -> Result<DidEbsiRegistryWriteResult, DidEbsiError> {
    let current = current_document_json
        .map(|bytes| parse_and_validate_did_ebsi_document(did, bytes, limits))
        .transpose()?;
    let proposed_state = if operation == DidEbsiRegistryOperation::DeactivateKeys {
        DidEbsiDocumentState::EffectivelyDeactivated
    } else {
        DidEbsiDocumentState::Active
    };
    let proposed = parse_and_validate_did_ebsi_document_for_state(
        did,
        proposed_document_json,
        limits,
        proposed_state,
    )?;
    validate_write_shape(
        operation,
        current.as_ref(),
        &proposed,
        authorization_method,
        target,
        effective_at,
    )?;

    let provider = provider.ok_or(DidEbsiError::new(DidEbsiErrorReason::ProviderUnavailable))?;
    if !provider.is_authenticated_for(operation) {
        return Err(DidEbsiError::new(
            DidEbsiErrorReason::ProviderUnauthenticated,
        ));
    }
    let response = provider
        .execute(DidEbsiRegistryWriteRequest {
            operation,
            did,
            current_document: current.as_ref(),
            proposed_document: &proposed,
            authorization_method,
            target,
            effective_at,
        })
        .map_err(map_provider_error)?;
    validate_response(operation, did, &proposed, response, limits)
}

fn validate_write_shape(
    operation: DidEbsiRegistryOperation,
    current: Option<&DidEbsiDocument>,
    proposed: &DidEbsiDocument,
    authorization_method: &str,
    target: Option<&str>,
    effective_at: Option<&str>,
) -> Result<(), DidEbsiError> {
    validate_effective_at(operation, effective_at)?;
    if operation == DidEbsiRegistryOperation::RegisterDocument {
        if current.is_some()
            || !proposed.capability_invocation_contains(authorization_method)
            || !proposed.has_verification_method(authorization_method)
        {
            return Err(DidEbsiError::new(DidEbsiErrorReason::UnauthorizedWrite));
        }
        return Ok(());
    }
    let current = current.ok_or(DidEbsiError::new(DidEbsiErrorReason::InvalidDocument))?;
    if !current.capability_invocation_contains(authorization_method)
        || !current.has_verification_method(authorization_method)
    {
        return Err(DidEbsiError::new(DidEbsiErrorReason::UnauthorizedWrite));
    }
    validate_transition(operation, current, proposed, target)
}

fn validate_effective_at(
    operation: DidEbsiRegistryOperation,
    effective_at: Option<&str>,
) -> Result<(), DidEbsiError> {
    let required = matches!(
        operation,
        DidEbsiRegistryOperation::RotateVerificationMethod
            | DidEbsiRegistryOperation::ExpireVerificationMethod
            | DidEbsiRegistryOperation::RevokeVerificationMethod
            | DidEbsiRegistryOperation::DeactivateKeys
    );
    match effective_at {
        Some(value)
            if !value.is_empty()
                && value.len() <= MAX_REGISTRY_METADATA_BYTES
                && OffsetDateTime::parse(value, &Rfc3339).is_ok() =>
        {
            Ok(())
        }
        None if !required => Ok(()),
        _ => Err(DidEbsiError::new(DidEbsiErrorReason::InvalidTimeline)),
    }
}

fn validate_response(
    operation: DidEbsiRegistryOperation,
    did: &str,
    proposed: &DidEbsiDocument,
    response: DidEbsiRegistryWriteResponse,
    limits: DidEbsiDocumentLimits,
) -> Result<DidEbsiRegistryWriteResult, DidEbsiError> {
    if response.operation != operation
        || response.version_id.is_empty()
        || response.version_id.len() > MAX_REGISTRY_METADATA_BYTES
        || response.version_sequence == 0
        || response.valid_from.is_empty()
        || response.valid_from.len() > MAX_REGISTRY_METADATA_BYTES
        || OffsetDateTime::parse(&response.valid_from, &Rfc3339).is_err()
    {
        return Err(DidEbsiError::new(DidEbsiErrorReason::ProviderFailure));
    }
    let state = if operation == DidEbsiRegistryOperation::DeactivateKeys {
        DidEbsiDocumentState::EffectivelyDeactivated
    } else {
        DidEbsiDocumentState::Active
    };
    let document = parse_and_validate_did_ebsi_document_for_state(
        did,
        &response.document_json,
        limits,
        state,
    )?;
    if document.value != proposed.value {
        return Err(DidEbsiError::new(DidEbsiErrorReason::ProviderFailure));
    }
    Ok(DidEbsiRegistryWriteResult {
        document,
        version_id: response.version_id.clone(),
        version_sequence: response.version_sequence,
        valid_from: response.valid_from.clone(),
    })
}

const fn map_provider_error(error: DidEbsiRegistryProviderError) -> DidEbsiError {
    match error.reason {
        DidEbsiRegistryProviderErrorReason::Unavailable => {
            DidEbsiError::new(DidEbsiErrorReason::ProviderUnavailable)
        }
        DidEbsiRegistryProviderErrorReason::Unauthenticated
        | DidEbsiRegistryProviderErrorReason::Unauthorized => {
            DidEbsiError::new(DidEbsiErrorReason::ProviderUnauthenticated)
        }
        DidEbsiRegistryProviderErrorReason::Transport
        | DidEbsiRegistryProviderErrorReason::RegistryRejected
        | DidEbsiRegistryProviderErrorReason::Timeout
        | DidEbsiRegistryProviderErrorReason::Cancelled => {
            DidEbsiError::new(DidEbsiErrorReason::ProviderFailure)
        }
    }
}

#[cfg(test)]
#[path = "registry_tests.rs"]
mod tests;
