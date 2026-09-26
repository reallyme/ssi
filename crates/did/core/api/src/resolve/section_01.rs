// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_did_method_ebsi::{
    validate_did_ebsi_resolution, write_did_ebsi_registry_document,
    AuthenticatedDidEbsiRegistryProvider, DidEbsiDocumentLimits, DidEbsiRegistryOperation,
    DidEbsiRegistryProviderError, DidEbsiRegistryProviderErrorReason, DidEbsiRegistryWriteRequest,
    DidEbsiRegistryWriteResponse, DidEbsiRegistryWriteResult, DidEbsiResolution,
    DidEbsiResolutionAssurance, DidEbsiResolveRequest,
};
use reallyme_did_method_web::{parse_did_web, DidWebDocument, DidWebMediaType};
use reallyme_did_types::DIDDocument;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::commands::{
    DidCreateRequest, DidDeactivateRequest, DidDesignateMessagingPreKeysRequest,
    DidReplaceCompromisedKeysRequest, DidRotateAllDocumentKeysRequest,
    DidRotateMessagingPreKeysRequest, DidRotateRelationshipKeysDocumentRequest,
    DidRotateSelectedKeysRequest, DidSetKeyRelationshipsDocumentRequest, DidUpdateRequest,
};
use crate::error::DidApiError;
use crate::parse::parse_did_url;
use crate::validate::{validate_did_with_history, DomainVerificationEnv};

/// Maximum DID or requested version identifier accepted by resolution.
pub const MAX_DID_RESOLUTION_IDENTIFIER_BYTES: usize = 4 * 1024;

/// Maximum provider metadata string accepted in a resolution result.
pub const MAX_DID_RESOLUTION_METADATA_BYTES: usize = 1024;

const DID_JSON_CONTENT_TYPE: &str = "application/did+json";
/// DID method validated by the generic provider resolution path.
const GENERIC_RESOLUTION_METHOD: &str = "me";
const DID_LD_JSON_CONTENT_TYPE: &str = "application/did+ld+json";

/// Request for provider-backed DID resolution.
#[derive(Clone, PartialEq, Eq)]
pub struct DidResolveRequest {
    /// DID to resolve. DID URL path, query, and fragment components are not valid here.
    pub did: String,
    /// Optional version identifier that must appear in the verified did:me chain.
    pub version_id: Option<String>,
    /// RFC 3339 instant at which a method registry version must have been valid.
    pub version_time: Option<String>,
    /// Lowest EBSI registry version sequence already accepted by the caller.
    pub minimum_version_sequence: Option<u64>,
    /// Minimum resolver assurance required by the caller.
    pub assurance: Option<DidResolutionAssurance>,
    /// Maximum age accepted for a cached provider observation.
    pub freshness: Option<DidResolutionFreshness>,
}
impl core::fmt::Debug for DidResolveRequest {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("DidResolveRequest(<redacted>)")
    }
}
impl Zeroize for DidResolveRequest {
    fn zeroize(&mut self) {
        self.did.zeroize();
        self.version_id.zeroize();
        self.version_time.zeroize();
        self.minimum_version_sequence = None;
    }
}
impl Drop for DidResolveRequest {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for DidResolveRequest {}

/// Maximum tolerated amount, in seconds, by which a provider `retrieved_at`
/// may lie in the future of the caller's trusted clock.
pub const MAX_DID_RESOLUTION_CLOCK_SKEW_SECONDS: u64 = 300;

/// Caller policy for cached resolution observations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DidResolutionFreshness {
    /// Maximum observation age. Zero requires a current provider observation.
    pub maximum_staleness_seconds: u64,
    /// Caller-trusted current time as Unix seconds. The provider-supplied
    /// `retrieved_at` is compared against this instant; it is never taken from
    /// the provider.
    pub trusted_now_unix_seconds: i64,
}

/// Resolution assurance achieved by the provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DidResolutionAssurance {
    /// The provider verified controller attestations.
    AttestationVerified,
    /// The provider verified a DID history chain.
    ChainVerified,
}

/// DID deactivation state returned by resolution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DidDeactivationStatus {
    /// The DID is active.
    Active,
    /// The DID has a terminal deactivation document.
    Deactivated,
    /// The DID is absent from the resolver's namespace.
    Absent,
}

/// Fixed resolution failure codes. Dynamic resolver text is intentionally not carried.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DidResolutionErrorCode {
    /// Resolver found no document for the DID.
    NotFound,
    /// Resolver could not validate a returned document.
    InvalidDocument,
    /// Resolver does not support the DID method.
    UnsupportedMethod,
    /// Resolver policy disallowed the operation.
    PolicyViolation,
    /// Resolver failed without exposing dynamic or private context.
    ResolverFailure,
}

/// Metadata produced by DID resolution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DidResolutionMetadata {
    /// Content type for the resolved document, when a document is present.
    pub content_type: Option<String>,
    /// Provider-supplied retrieval timestamp.
    pub retrieved_at: Option<String>,
    /// Stable resolver identifier.
    pub resolver: Option<String>,
    /// Fixed resolver error code.
    pub error: Option<DidResolutionErrorCode>,
    /// Assurance level achieved by provider-side verification.
    pub assurance_achieved: Option<DidResolutionAssurance>,
    /// Resolved did:me sequence number.
    pub sequence: Option<u64>,
    /// Active, deactivated, or absent status.
    pub deactivation_status: DidDeactivationStatus,
}

/// DID document metadata returned by DID resolution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DidDocumentMetadata {
    /// Provider-supplied creation timestamp.
    pub created: Option<String>,

    /// Provider-supplied update timestamp.
    pub updated: Option<String>,

    /// Whether the returned document is a terminal deactivation document.
    pub deactivated: bool,

    /// Current version identifier.
    pub version_id: Option<String>,

    /// Next version identifier, if known.
    pub next_version_id: Option<String>,

    /// Inclusive registry validity bound for the selected version.
    pub valid_from: Option<String>,

    /// Exclusive registry validity bound, absent for the current version.
    pub valid_until: Option<String>,
}

/// Provider-backed DID resolution result.
#[derive(Debug, Clone)]
pub struct DidResolutionResult {
    /// Resolved DID document. Absent DIDs must not carry a document.
    pub document: Option<DIDDocument>,

    /// Predecessor did:me documents, genesis first, ending with the document
    /// directly preceding `document`. Required whenever the resolved did:me
    /// document has `sequence >= 2`, because a non-genesis document can only be
    /// authenticated against its previous core state. Must be empty otherwise.
    pub history: Vec<DIDDocument>,

    /// Resolution metadata.
    pub resolution_metadata: DidResolutionMetadata,

    /// Document metadata. Required whenever `document` is present.
    pub document_metadata: Option<DidDocumentMetadata>,
}

/// Provider result for a did:web HTTPS resolution.
pub struct DidWebProviderResolution {
    /// Validated document for an active DID.
    pub document: Option<DidWebDocument>,
    /// Accepted response media type for an active DID.
    pub media_type: Option<DidWebMediaType>,
    /// Active or absent state. did:web deactivation is represented by absence.
    pub deactivation_status: DidDeactivationStatus,
}

impl core::fmt::Debug for DidWebProviderResolution {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("DidWebProviderResolution(<redacted>)")
    }
}

/// Non-cloneable owner for a validated provider resolution result.
///
/// Provider results contain a complete identifying document and resolver
/// metadata. Canonical dispatch keeps that material in this owner until the
/// generated response has been constructed, then clears it deterministically.
pub struct SensitiveDidResolutionResult {
    inner: DidResolutionResult,
}

impl SensitiveDidResolutionResult {
    fn from_result(inner: DidResolutionResult) -> Self {
        Self { inner }
    }

    /// Borrow the validated provider result without transferring ownership.
    #[must_use]
    pub fn as_result(&self) -> &DidResolutionResult {
        &self.inner
    }
}

impl core::fmt::Debug for SensitiveDidResolutionResult {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("SensitiveDidResolutionResult(<redacted>)")
    }
}

impl Zeroize for SensitiveDidResolutionResult {
    fn zeroize(&mut self) {
        if let Some(document) = &mut self.inner.document {
            document.zeroize();
        }
        self.inner.document = None;
        for document in &mut self.inner.history {
            document.zeroize();
        }
        self.inner.history.clear();
        self.inner.resolution_metadata.content_type.zeroize();
        self.inner.resolution_metadata.retrieved_at.zeroize();
        self.inner.resolution_metadata.resolver.zeroize();
        self.inner.resolution_metadata.sequence = None;
        if let Some(metadata) = &mut self.inner.document_metadata {
            metadata.created.zeroize();
            metadata.updated.zeroize();
            metadata.deactivated = false;
            metadata.version_id.zeroize();
            metadata.next_version_id.zeroize();
            metadata.valid_from.zeroize();
            metadata.valid_until.zeroize();
        }
        self.inner.document_metadata = None;
    }
}

impl Drop for SensitiveDidResolutionResult {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for SensitiveDidResolutionResult {}

/// Provider capabilities used by typed dispatch policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DidProviderCapability {
    /// Create a DID through provider-owned key, storage, and publication policy.
    Create,

    /// Update a DID through provider-owned authorization, storage, and publication policy.
    Update,

    /// Deactivate a DID through provider-owned authorization, storage, and publication policy.
    Deactivate,

    /// Rotate explicitly selected DID keys through provider-owned key policy.
    RotateSelectedKeys,

    /// Rotate every key assigned to one supported DID relationship.
    RotateRelationshipKeys,

    /// Replace compromised keys through provider-owned recovery policy.
    ReplaceCompromisedKeys,

    /// Rotate every verification method through provider-owned key policy.
    RotateAllKeys,

    /// Assign existing verification methods to DID relationships.
    SetKeyRelationships,

    /// Designate MessagingService pre-keys through provider-owned update policy.
    DesignateMessagingPreKeys,

    /// Rotate a published MessagingService hybrid pre-key set.
    RotateMessagingPreKeys,

    /// Resolve a DID and return a validated resolution result.
    Resolve,
}

/// Provider interface for DID resolution.
pub trait DidProvider {
    /// Report whether this provider intentionally enables a capability.
    ///
    /// The default is fail-closed so adding a provider object cannot silently
    /// make a network-backed operation executable or advertised.
    fn supports_capability(&self, _capability: DidProviderCapability) -> bool {
        false
    }

    /// Create a DID using caller-owned storage/publication policy.
    fn create_did(&self, _request: DidCreateRequest) -> Result<DIDDocument, DidApiError> {
        Err(DidApiError::ProviderCapabilityUnsupported)
    }

    /// Update a DID using provider-owned key and publication policy.
    fn update_did(&self, _request: &DidUpdateRequest) -> Result<DIDDocument, DidApiError> {
        Err(DidApiError::ProviderCapabilityUnsupported)
    }

    /// Resolve a DID using caller-owned I/O and resolver policy.
    fn resolve_did(&self, request: DidResolveRequest) -> Result<DidResolutionResult, DidApiError>;

    /// Resolve did:web through an injected HTTPS resolver implementation.
    fn resolve_did_web(&self, _did: &str) -> Result<DidWebProviderResolution, DidApiError> {
        Err(DidApiError::ProviderCapabilityUnsupported)
    }

    /// Resolve legal-entity did:ebsi through an injected registry adapter.
    fn resolve_did_ebsi(
        &self,
        _request: DidEbsiResolveRequest,
    ) -> Result<DidEbsiResolution, DidApiError> {
        Err(DidApiError::ProviderCapabilityUnsupported)
    }
    /// Report whether this provider is authenticated for the exact EBSI operation.
    fn is_authenticated_for_did_ebsi(&self, _operation: DidEbsiRegistryOperation) -> bool {
        false
    }
    /// Execute an EBSI write without exposing tokens, signing material, or response text.
    fn execute_did_ebsi_registry_write(
        &self,
        _request: DidEbsiRegistryWriteRequest<'_>,
    ) -> Result<DidEbsiRegistryWriteResponse, DidEbsiRegistryProviderError> {
        Err(DidEbsiRegistryProviderError {
            reason: DidEbsiRegistryProviderErrorReason::Unavailable,
        })
    }
    /// Publish a validated did:web document through an authenticated host adapter.
    fn create_did_web(
        &self,
        _did: &str,
        _document: &DidWebDocument,
    ) -> Result<DidWebDocument, DidApiError> {
        Err(DidApiError::ProviderCapabilityUnsupported)
    }

    /// Replace a validated did:web document through an authenticated host adapter.
    fn update_did_web(
        &self,
        _did: &str,
        _document: &DidWebDocument,
    ) -> Result<DidWebDocument, DidApiError> {
        Err(DidApiError::ProviderCapabilityUnsupported)
    }

    /// Remove a did:web document through an authenticated host adapter.
    fn deactivate_did_web(&self, _did: &str) -> Result<(), DidApiError> {
        Err(DidApiError::ProviderCapabilityUnsupported)
    }

    /// Deactivate a DID through method/provider-owned policy.
    fn deactivate_did(&self, _request: &DidDeactivateRequest) -> Result<DIDDocument, DidApiError> {
        Err(DidApiError::ProviderCapabilityUnsupported)
    }

    /// Rotate explicit verification method keys through provider-owned policy.
    fn rotate_did_keys(
        &self,
        _request: &DidRotateSelectedKeysRequest,
    ) -> Result<DIDDocument, DidApiError> {
        Err(DidApiError::ProviderCapabilityUnsupported)
    }

    /// Rotate all keys assigned to a relationship through provider-owned policy.
    fn rotate_did_relationship_keys(
        &self,
        _request: &DidRotateRelationshipKeysDocumentRequest,
    ) -> Result<DIDDocument, DidApiError> {
        Err(DidApiError::ProviderCapabilityUnsupported)
    }

    /// Replace compromised keys through provider-owned recovery policy.
    fn replace_compromised_did_keys(
        &self,
        _request: &DidReplaceCompromisedKeysRequest,
    ) -> Result<DIDDocument, DidApiError> {
        Err(DidApiError::ProviderCapabilityUnsupported)
    }

    /// Rotate all DID keys through provider-owned policy.
    fn rotate_all_did_keys(
        &self,
        _request: &DidRotateAllDocumentKeysRequest,
    ) -> Result<DIDDocument, DidApiError> {
        Err(DidApiError::ProviderCapabilityUnsupported)
    }

    /// Assign DID key relationships through provider-owned policy.
    fn set_did_key_relationships(
        &self,
        _request: &DidSetKeyRelationshipsDocumentRequest,
    ) -> Result<DIDDocument, DidApiError> {
        Err(DidApiError::ProviderCapabilityUnsupported)
    }

    /// Designate public MessagingService pre-key references and publish the transition.
    fn designate_messaging_pre_keys(
        &self,
        _request: &DidDesignateMessagingPreKeysRequest,
    ) -> Result<DIDDocument, DidApiError> {
        Err(DidApiError::ProviderCapabilityUnsupported)
    }

    /// Rotate every verification method in one published messaging pre-key set.
    fn rotate_messaging_pre_keys(
        &self,
        _request: &DidRotateMessagingPreKeysRequest,
    ) -> Result<DIDDocument, DidApiError> {
        Err(DidApiError::ProviderCapabilityUnsupported)
    }
}
