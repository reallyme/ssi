// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Authenticated did:web hosting and publication boundary.

use crate::document::{parse_and_validate_did_web_document, DidWebDocument, DidWebDocumentLimits};
use crate::error::{DidWebError, DidWebErrorReason, DidWebHostingError};
use crate::method::{did_web_document_url, parse_did_web};

/// Closed hosting operations required by the ReallyMe did:web profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DidWebHostingOperation {
    /// Publish a previously absent document.
    Create,
    /// Replace an existing document.
    Update,
    /// Remove or make an existing document unavailable.
    Deactivate,
}

/// Privacy-safe receipt proving which class of operation completed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DidWebHostingReceipt {
    /// Operation confirmed by the adapter.
    pub operation: DidWebHostingOperation,
}

/// Borrowed publication request passed to a hosting adapter.
pub struct DidWebPublicationRequest<'a> {
    /// Mutation being requested.
    pub operation: DidWebHostingOperation,
    /// Canonical DID being mutated.
    pub did: &'a str,
    /// Canonical HTTPS publication location.
    pub resolution_url: &'a str,
    /// Validated document for create/update; absent for deactivation.
    pub document: Option<&'a DidWebDocument>,
}

/// Injected provider for an authenticated, provider-specific hosting API.
///
/// Implementations must authenticate before mutation and must bind that
/// authorization to the exact origin and resource supplied in the request.
/// No universal write API is implied by this contract.
pub trait AuthenticatedDidWebHostingProvider {
    /// Report whether authentication is valid for this exact operation class.
    fn is_authenticated_for(&self, operation: DidWebHostingOperation) -> bool;

    /// Execute one mutation without returning backend text or sensitive context.
    fn execute(
        &self,
        request: DidWebPublicationRequest<'_>,
    ) -> Result<DidWebHostingReceipt, DidWebHostingError>;
}

/// Validated document plus a provider receipt for create or update.
pub struct DidWebPublicationResult {
    /// Validated document submitted to the adapter.
    pub document: DidWebDocument,
    /// Adapter confirmation for the requested operation.
    pub receipt: DidWebHostingReceipt,
}

impl core::fmt::Debug for DidWebPublicationResult {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("DidWebPublicationResult(<redacted>)")
    }
}

/// Validate and publish a new did:web document.
pub fn create_did_web_document(
    provider: Option<&dyn AuthenticatedDidWebHostingProvider>,
    did: &str,
    document_json: &[u8],
    limits: DidWebDocumentLimits,
) -> Result<DidWebPublicationResult, DidWebError> {
    publish_document(
        provider,
        DidWebHostingOperation::Create,
        did,
        document_json,
        limits,
    )
}

/// Validate and replace an existing did:web document at the same location.
pub fn update_did_web_document(
    provider: Option<&dyn AuthenticatedDidWebHostingProvider>,
    did: &str,
    document_json: &[u8],
    limits: DidWebDocumentLimits,
) -> Result<DidWebPublicationResult, DidWebError> {
    publish_document(
        provider,
        DidWebHostingOperation::Update,
        did,
        document_json,
        limits,
    )
}

/// Remove a did:web document through the authenticated hosting provider.
pub fn deactivate_did_web_document(
    provider: Option<&dyn AuthenticatedDidWebHostingProvider>,
    did: &str,
) -> Result<DidWebHostingReceipt, DidWebError> {
    let identifier = parse_did_web(did)?;
    let resolution_url = did_web_document_url(identifier.as_str())?;
    let provider = authenticated_provider(provider, DidWebHostingOperation::Deactivate)?;
    let receipt = provider.execute(DidWebPublicationRequest {
        operation: DidWebHostingOperation::Deactivate,
        did: identifier.as_str(),
        resolution_url: &resolution_url,
        document: None,
    })?;
    validate_receipt(receipt, DidWebHostingOperation::Deactivate)
}

fn publish_document(
    provider: Option<&dyn AuthenticatedDidWebHostingProvider>,
    operation: DidWebHostingOperation,
    did: &str,
    document_json: &[u8],
    limits: DidWebDocumentLimits,
) -> Result<DidWebPublicationResult, DidWebError> {
    let identifier = parse_did_web(did)?;
    let document = parse_and_validate_did_web_document(&identifier, document_json, limits)?;
    let resolution_url = did_web_document_url(identifier.as_str())?;
    let provider = authenticated_provider(provider, operation)?;
    let receipt = provider.execute(DidWebPublicationRequest {
        operation,
        did: identifier.as_str(),
        resolution_url: &resolution_url,
        document: Some(&document),
    })?;
    let receipt = validate_receipt(receipt, operation)?;
    Ok(DidWebPublicationResult { document, receipt })
}

fn authenticated_provider(
    provider: Option<&dyn AuthenticatedDidWebHostingProvider>,
    operation: DidWebHostingOperation,
) -> Result<&dyn AuthenticatedDidWebHostingProvider, DidWebError> {
    let provider = provider.ok_or(DidWebError::new(DidWebErrorReason::ProviderUnavailable))?;
    if !provider.is_authenticated_for(operation) {
        return Err(DidWebError::new(DidWebErrorReason::ProviderUnauthenticated));
    }
    Ok(provider)
}

fn validate_receipt(
    receipt: DidWebHostingReceipt,
    expected: DidWebHostingOperation,
) -> Result<DidWebHostingReceipt, DidWebError> {
    if receipt.operation != expected {
        return Err(DidWebError::new(DidWebErrorReason::ProviderFailure));
    }
    Ok(receipt)
}
