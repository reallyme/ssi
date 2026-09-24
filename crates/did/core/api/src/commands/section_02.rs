// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

/// Canonical request for relationship-scoped DID key rotation.
///
/// The selected verification methods are derived from the authoritative
/// document, preventing a caller from presenting a partial relationship as a
/// complete relationship rotation.
pub struct DidRotateRelationshipKeysDocumentRequest {
    /// Active DID document whose complete relationship must rotate.
    pub document: DIDDocument,

    /// Supported relationship whose referenced keys must all rotate.
    pub relationship: RekeyRelationship,

    /// Host-supplied timestamp for proof regeneration when needed.
    pub created: Option<String>,
}

impl core::fmt::Debug for DidRotateRelationshipKeysDocumentRequest {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("DidRotateRelationshipKeysDocumentRequest(<redacted>)")
    }
}

impl Zeroize for DidRotateRelationshipKeysDocumentRequest {
    fn zeroize(&mut self) {
        self.document.zeroize();
        self.created.zeroize();
    }
}

impl Drop for DidRotateRelationshipKeysDocumentRequest {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for DidRotateRelationshipKeysDocumentRequest {}

/// Canonical request for provider-backed all-key rotation.
///
/// Every verification method in the authoritative document is a mandatory
/// target. The request deliberately has no exclusion or selection field.
pub struct DidRotateAllDocumentKeysRequest {
    /// Active DID document whose complete verification-method set must rotate.
    pub document: DIDDocument,

    /// Host-supplied timestamp for proof regeneration when needed.
    pub created: Option<String>,
}

impl core::fmt::Debug for DidRotateAllDocumentKeysRequest {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("DidRotateAllDocumentKeysRequest(<redacted>)")
    }
}

impl Zeroize for DidRotateAllDocumentKeysRequest {
    fn zeroize(&mut self) {
        self.document.zeroize();
        self.created.zeroize();
    }
}

impl Drop for DidRotateAllDocumentKeysRequest {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for DidRotateAllDocumentKeysRequest {}

/// Canonical authoritative-document relationship-assignment request.
pub struct DidSetKeyRelationshipsDocumentRequest {
    /// Active document whose existing verification methods are reassigned.
    pub document: DIDDocument,

    /// Replacement authentication references; `None` preserves the relationship.
    pub authentication: Option<Vec<String>>,

    /// Replacement assertion-method references; `None` preserves the relationship.
    pub assertion_method: Option<Vec<String>>,

    /// Replacement capability-invocation references and update-policy allowlist.
    pub capability_invocation: Option<Vec<String>>,

    /// Replacement key-agreement references; `None` preserves the relationship.
    pub key_agreement: Option<Vec<String>>,

    /// Replacement update-policy threshold, valid only with capability invocation.
    pub threshold: Option<u64>,

    /// Host-supplied timestamp for proof regeneration when needed.
    pub created: Option<String>,
}

impl core::fmt::Debug for DidSetKeyRelationshipsDocumentRequest {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("DidSetKeyRelationshipsDocumentRequest(<redacted>)")
    }
}

impl Zeroize for DidSetKeyRelationshipsDocumentRequest {
    fn zeroize(&mut self) {
        self.document.zeroize();
        self.authentication.zeroize();
        self.assertion_method.zeroize();
        self.capability_invocation.zeroize();
        self.key_agreement.zeroize();
        self.threshold.zeroize();
        self.created.zeroize();
    }
}

impl Drop for DidSetKeyRelationshipsDocumentRequest {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for DidSetKeyRelationshipsDocumentRequest {}

/// Canonical provider-backed MessagingService pre-key designation request.
///
/// The request carries only the authoritative public DID state and public
/// key-agreement references. Provider key handles, authorization credentials,
/// private keys, persistence details, and publication receipts remain outside
/// the protobuf and domain command contracts.
pub struct DidDesignateMessagingPreKeysRequest {
    /// Active document whose MessagingService endpoint must be designated.
    pub document: DIDDocument,

    /// Service identifier to insert or replace.
    pub service_id: String,

    /// Relay or delivery URI published by the service.
    pub uri: String,

    /// Hybrid classical and post-quantum key-agreement method references.
    pub pre_keys: Vec<String>,

    /// Host-supplied timestamp for proof regeneration when needed.
    pub created: Option<String>,
}

impl core::fmt::Debug for DidDesignateMessagingPreKeysRequest {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("DidDesignateMessagingPreKeysRequest(<redacted>)")
    }
}

impl Zeroize for DidDesignateMessagingPreKeysRequest {
    fn zeroize(&mut self) {
        self.document.zeroize();
        self.service_id.zeroize();
        self.uri.zeroize();
        self.pre_keys.zeroize();
        self.created.zeroize();
    }
}

impl Drop for DidDesignateMessagingPreKeysRequest {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for DidDesignateMessagingPreKeysRequest {}

/// Canonical provider-backed MessagingService pre-key rotation request.
///
/// The selected verification methods are derived from the validated service
/// snapshot. Callers cannot omit one member of the published hybrid set or
/// add unrelated verification methods to the rotation.
pub struct DidRotateMessagingPreKeysRequest {
    /// Active document publishing the MessagingService pre-key set.
    pub document: DIDDocument,

    /// Existing MessagingService identifier whose complete pre-key set rotates.
    pub service_id: String,

    /// Host-supplied timestamp for proof regeneration when needed.
    pub created: Option<String>,
}

impl core::fmt::Debug for DidRotateMessagingPreKeysRequest {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("DidRotateMessagingPreKeysRequest(<redacted>)")
    }
}

impl Zeroize for DidRotateMessagingPreKeysRequest {
    fn zeroize(&mut self) {
        self.document.zeroize();
        self.service_id.zeroize();
        self.created.zeroize();
    }
}

impl Drop for DidRotateMessagingPreKeysRequest {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for DidRotateMessagingPreKeysRequest {}

/// Provider-backed `identity.dids.create`.
pub fn create_did_with_provider<P: DidProvider + ?Sized>(
    provider: &P,
    request: DidCreateRequest,
) -> Result<DIDDocument, DidApiError> {
    let document = provider.create_did(request)?;
    validate_created_document(&document)?;
    Ok(document)
}

/// Create through an injected provider and adopt the validated document into
/// a non-cloneable zeroizing owner for canonical dispatch.
pub fn create_did_with_provider_owned<P: DidProvider + ?Sized>(
    provider: &P,
    request: DidCreateRequest,
) -> Result<SensitiveDidCreatedDocument, DidApiError> {
    create_did_with_provider(provider, request).map(SensitiveDidCreatedDocument::from_document)
}

fn validate_created_document(document: &DIDDocument) -> Result<(), DidApiError> {
    if document.sequence != 1 || !document.key_history.is_empty() {
        return Err(DidApiError::CreationResultInvalid);
    }

    let validation = validate_did(
        document,
        DomainVerificationEnv {
            resolve_txt: None,
            fetch_url: None,
        },
    );
    if !validation.ok {
        return Err(DidApiError::CreationResultInvalid);
    }
    Ok(())
}

/// Provider-backed `identity.dids.update` with pre-dispatch request validation
/// and post-provider transition validation.
pub fn update_did_with_provider<P: DidProvider + ?Sized>(
    provider: &P,
    request: DidUpdateRequest,
) -> Result<DIDDocument, DidApiError> {
    validate_update_request(&request)?;
    let document = provider.update_did(&request)?;
    validate_updated_document(&request, &document)?;
    Ok(document)
}

/// Update through an injected provider and adopt the validated document into
/// a non-cloneable zeroizing owner for canonical dispatch.
pub fn update_did_with_provider_owned<P: DidProvider + ?Sized>(
    provider: &P,
    request: DidUpdateRequest,
) -> Result<SensitiveDidUpdatedDocument, DidApiError> {
    update_did_with_provider(provider, request).map(SensitiveDidUpdatedDocument::from_document)
}

fn validate_update_request(request: &DidUpdateRequest) -> Result<(), DidApiError> {
    let document = &request.document;
    let validation = validate_did(
        document,
        DomainVerificationEnv {
            resolve_txt: None,
            fetch_url: None,
        },
    );
    let has_update_authority = document
        .update_policy
        .as_ref()
        .is_some_and(|policy| !policy.allowed_verification_methods.is_empty());
    if !validation.ok || !has_update_authority {
        return Err(DidApiError::UpdateRequestInvalid);
    }

    if request
        .services
        .as_ref()
        .is_some_and(|values| values.len() > MAX_DID_UPDATE_COLLECTION_ENTRIES)
        || request
            .also_known_as
            .as_ref()
            .is_some_and(|values| values.len() > MAX_DID_UPDATE_COLLECTION_ENTRIES)
        || request
            .domain_verification
            .as_ref()
            .is_some_and(|values| values.len() > MAX_DID_UPDATE_COLLECTION_ENTRIES)
    {
        return Err(DidApiError::UpdateRequestInvalid);
    }

    if request
        .also_known_as
        .as_ref()
        .is_some_and(|values| !text_values_are_valid(values))
        || request.services.as_ref().is_some_and(|services| {
            services
                .iter()
                .any(|service| !text_is_valid(&service.id) || !text_is_valid(&service.service_type))
        })
        || request
            .domain_verification
            .as_ref()
            .is_some_and(|verifications| {
                verifications.iter().any(|verification| {
                    !text_is_valid(&verification.domain)
                        || !matches!(verification.method.as_str(), "dns" | "wellknown")
                })
            })
        || !string_property_update_is_valid(request.user_verification_method.as_ref())
        || !string_property_update_is_valid(request.device_model.as_ref())
    {
        return Err(DidApiError::UpdateRequestInvalid);
    }

    // Validate the caller's projected public shape before invoking a provider.
    // The temporary clone is explicitly zeroized because it duplicates the
    // complete identifying document in order to reuse the authoritative
    // structural and service validators without weakening their context.
    let mut projected = Zeroizing::new(document.clone());
    if let Some(services) = request.services.as_ref() {
        projected.service = services.clone();
    }
    if let Some(also_known_as) = request.also_known_as.as_ref() {
        projected.also_known_as = also_known_as.clone();
    }
    projected.hardware_bound =
        expected_bool_property(request.hardware_bound, document.hardware_bound);
    projected.biometric_protected =
        expected_bool_property(request.biometric_protected, document.biometric_protected);
    projected.user_verification_method = expected_owned_string_property(
        request.user_verification_method.as_ref(),
        document.user_verification_method.as_ref(),
    );
    projected.device_model = expected_owned_string_property(
        request.device_model.as_ref(),
        document.device_model.as_ref(),
    );
    if let Some(domain_verification) = request.domain_verification.as_ref() {
        projected.domain_verification = domain_verification.clone();
    }

    if !validate_did_me_structure(&projected).ok
        || !validate_services(&projected).ok
        || !validate_all_domain_bindings(&projected.id, &projected.domain_verification).is_empty()
    {
        return Err(DidApiError::UpdateRequestInvalid);
    }
    Ok(())
}
