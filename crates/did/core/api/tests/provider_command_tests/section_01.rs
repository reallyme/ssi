// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_did_api::{
    create_did, create_did_with_provider, create_did_with_provider_owned, deactivate_did,
    deactivate_did_with_provider, deactivate_did_with_provider_owned, designate_messaging_pre_keys,
    designate_messaging_pre_keys_with_provider, designate_messaging_pre_keys_with_provider_owned,
    replace_compromised_did_keys_with_provider, replace_compromised_did_keys_with_provider_owned,
    replace_compromised_keys, rotate_all_did_keys_with_provider,
    rotate_all_did_keys_with_provider_owned, rotate_all_keys, rotate_did_keys_with_provider,
    rotate_did_keys_with_provider_owned, rotate_did_relationship_keys_with_provider,
    rotate_did_relationship_keys_with_provider_owned, rotate_keys, rotate_messaging_pre_keys,
    rotate_messaging_pre_keys_with_provider, rotate_messaging_pre_keys_with_provider_owned,
    rotate_relationship_keys, set_did_key_relationships_with_provider,
    set_did_key_relationships_with_provider_owned, set_key_relationships, update_did,
    update_did_with_provider, update_did_with_provider_owned, CreateConfig, DidApiError,
    DidBoolPropertyUpdate, DidCreateRequest, DidDeactivateRequest,
    DidDesignateMessagingPreKeysRequest, DidMethod, DidProfile, DidProvider, DidProviderCapability,
    DidReplaceCompromisedKeysRequest, DidResolutionResult, DidResolveRequest,
    DidRotateAllDocumentKeysRequest, DidRotateMessagingPreKeysRequest,
    DidRotateRelationshipKeysDocumentRequest, DidRotateSelectedKeysRequest,
    DidSetKeyRelationshipsDocumentRequest, DidStringPropertyUpdate, DidUpdateRequest,
    RekeyRelationship, RelationshipAssignmentConfig, UpdateConfig,
};
use reallyme_did_types::{DIDDocument, Service};
use zeroize::Zeroize;

struct ResolveOnlyProvider;

impl DidProvider for ResolveOnlyProvider {
    fn resolve_did(&self, _request: DidResolveRequest) -> Result<DidResolutionResult, DidApiError> {
        Err(DidApiError::ProviderCapabilityUnsupported)
    }
}

struct SuccessfulCreateProvider {
    document: DIDDocument,
}

struct SuccessfulUpdateProvider {
    document: DIDDocument,
}

struct SuccessfulDeactivateProvider {
    document: DIDDocument,
}

struct SuccessfulRotateProvider {
    document: DIDDocument,
}

impl DidProvider for SuccessfulUpdateProvider {
    fn supports_capability(&self, capability: DidProviderCapability) -> bool {
        capability == DidProviderCapability::Update
    }

    fn update_did(&self, _request: &DidUpdateRequest) -> Result<DIDDocument, DidApiError> {
        Ok(self.document.clone())
    }

    fn resolve_did(&self, _request: DidResolveRequest) -> Result<DidResolutionResult, DidApiError> {
        Err(DidApiError::ProviderCapabilityUnsupported)
    }
}

impl DidProvider for SuccessfulCreateProvider {
    fn supports_capability(&self, capability: DidProviderCapability) -> bool {
        capability == DidProviderCapability::Create
    }

    fn create_did(&self, _request: DidCreateRequest) -> Result<DIDDocument, DidApiError> {
        Ok(self.document.clone())
    }

    fn resolve_did(&self, _request: DidResolveRequest) -> Result<DidResolutionResult, DidApiError> {
        Err(DidApiError::ProviderCapabilityUnsupported)
    }
}

impl DidProvider for SuccessfulDeactivateProvider {
    fn supports_capability(&self, capability: DidProviderCapability) -> bool {
        capability == DidProviderCapability::Deactivate
    }

    fn deactivate_did(&self, _request: &DidDeactivateRequest) -> Result<DIDDocument, DidApiError> {
        Ok(self.document.clone())
    }

    fn resolve_did(&self, _request: DidResolveRequest) -> Result<DidResolutionResult, DidApiError> {
        Err(DidApiError::ProviderCapabilityUnsupported)
    }
}

impl DidProvider for SuccessfulRotateProvider {
    fn supports_capability(&self, capability: DidProviderCapability) -> bool {
        matches!(
            capability,
            DidProviderCapability::RotateSelectedKeys
                | DidProviderCapability::RotateRelationshipKeys
                | DidProviderCapability::ReplaceCompromisedKeys
                | DidProviderCapability::RotateAllKeys
                | DidProviderCapability::SetKeyRelationships
                | DidProviderCapability::DesignateMessagingPreKeys
                | DidProviderCapability::RotateMessagingPreKeys
        )
    }

    fn rotate_did_keys(
        &self,
        _request: &DidRotateSelectedKeysRequest,
    ) -> Result<DIDDocument, DidApiError> {
        Ok(self.document.clone())
    }

    fn rotate_did_relationship_keys(
        &self,
        _request: &DidRotateRelationshipKeysDocumentRequest,
    ) -> Result<DIDDocument, DidApiError> {
        Ok(self.document.clone())
    }

    fn replace_compromised_did_keys(
        &self,
        _request: &DidReplaceCompromisedKeysRequest,
    ) -> Result<DIDDocument, DidApiError> {
        Ok(self.document.clone())
    }

    fn rotate_all_did_keys(
        &self,
        _request: &DidRotateAllDocumentKeysRequest,
    ) -> Result<DIDDocument, DidApiError> {
        Ok(self.document.clone())
    }

    fn set_did_key_relationships(
        &self,
        _request: &DidSetKeyRelationshipsDocumentRequest,
    ) -> Result<DIDDocument, DidApiError> {
        Ok(self.document.clone())
    }

    fn designate_messaging_pre_keys(
        &self,
        _request: &DidDesignateMessagingPreKeysRequest,
    ) -> Result<DIDDocument, DidApiError> {
        Ok(self.document.clone())
    }

    fn rotate_messaging_pre_keys(
        &self,
        _request: &DidRotateMessagingPreKeysRequest,
    ) -> Result<DIDDocument, DidApiError> {
        Ok(self.document.clone())
    }

    fn resolve_did(&self, _request: DidResolveRequest) -> Result<DidResolutionResult, DidApiError> {
        Err(DidApiError::ProviderCapabilityUnsupported)
    }
}

fn active_document(did: &str) -> Option<(DIDDocument, reallyme_did_api::KeySet)> {
    create_did(
        CreateConfig {
            profile: Some(DidProfile::CoreIdentity),
            also_known_as: None,
            hardware_bound: None,
            biometric_protected: None,
            user_verification_method: None,
            device_model: None,
            services: None,
            update_policy: None,
            domain_verification: None,
            verification_methods: None,
            authentication: None,
            assertion: None,
            invocation: None,
            key_agreement: None,
            created: Some("2026-01-01T00:00:00Z".into()),
        },
        did,
    )
    .ok()
}

fn selected_rotation_documents(did: &str) -> Option<(DIDDocument, DIDDocument)> {
    let (old_document, key_set) = active_document(did)?;
    let (rotated_document, rotated_key_set) = rotate_keys(
        &old_document,
        &key_set,
        &["#ed25519".to_owned()],
        Some("2026-01-02T00:00:00Z".to_owned()),
    )
    .ok()?;
    drop(rotated_key_set);
    drop(key_set);
    Some((old_document, rotated_document))
}

fn relationship_rotation_documents(did: &str) -> Option<(DIDDocument, DIDDocument)> {
    let (old_document, key_set) = active_document(did)?;
    let (rotated_document, rotated_key_set) = rotate_relationship_keys(
        &old_document,
        &key_set,
        RekeyRelationship::Authentication,
        Some("2026-01-02T00:00:00Z".to_owned()),
    )
    .ok()?;
    drop(rotated_key_set);
    drop(key_set);
    Some((old_document, rotated_document))
}

fn compromised_key_replacement_documents(did: &str) -> Option<(DIDDocument, DIDDocument)> {
    let (old_document, key_set) = active_document(did)?;
    let (replaced_document, replacement_key_set) = replace_compromised_keys(
        &old_document,
        &key_set,
        &["#x25519".to_owned()],
        Some("2026-01-02T00:00:00Z".to_owned()),
    )
    .ok()?;
    drop(replacement_key_set);
    drop(key_set);
    Some((old_document, replaced_document))
}

fn all_key_rotation_documents(did: &str) -> Option<(DIDDocument, DIDDocument)> {
    let (old_document, key_set) = active_document(did)?;
    let (rotated_document, rotated_key_set) = rotate_all_keys(
        &old_document,
        &key_set,
        Some("2026-01-02T00:00:00Z".to_owned()),
    )
    .ok()?;
    drop(rotated_key_set);
    drop(key_set);
    Some((old_document, rotated_document))
}

fn relationship_assignment_documents(did: &str) -> Option<(DIDDocument, DIDDocument)> {
    let (old_document, key_set) = active_document(did)?;
    let (assigned_document, assigned_key_set) = set_key_relationships(
        &old_document,
        &key_set,
        RelationshipAssignmentConfig {
            authentication: Some(vec!["#mldsa87-root".to_owned()]),
            assertion: None,
            invocation: None,
            key_agreement: None,
            threshold: None,
            created: Some("2026-01-02T00:00:00Z".to_owned()),
        },
    )
    .ok()?;
    drop(assigned_key_set);
    drop(key_set);
    Some((old_document, assigned_document))
}

fn messaging_designation_documents(did: &str) -> Option<(DIDDocument, DIDDocument)> {
    let (old_document, key_set) = active_document(did)?;
    let (designated_document, designated_key_set) = designate_messaging_pre_keys(
        &old_document,
        &key_set,
        "#messaging".to_owned(),
        "https://relay.example/inbox/subject".to_owned(),
        vec!["#x25519".to_owned(), "#mlkem768".to_owned()],
        Some("2026-01-02T00:00:00Z".to_owned()),
    )
    .ok()?;
    drop(designated_key_set);
    drop(key_set);
    Some((old_document, designated_document))
}

fn messaging_rotation_documents(did: &str) -> Option<(DIDDocument, DIDDocument)> {
    let (old_document, key_set) = active_document(did)?;
    let (designated_document, designated_key_set) = designate_messaging_pre_keys(
        &old_document,
        &key_set,
        "#messaging".to_owned(),
        "https://relay.example/inbox/subject".to_owned(),
        vec!["#x25519".to_owned(), "#mlkem768".to_owned()],
        Some("2026-01-02T00:00:00Z".to_owned()),
    )
    .ok()?;
    let (rotated_document, rotated_key_set) = rotate_messaging_pre_keys(
        &designated_document,
        &designated_key_set,
        "#messaging",
        Some("2026-01-03T00:00:00Z".to_owned()),
    )
    .ok()?;
    drop(rotated_key_set);
    drop(designated_key_set);
    drop(key_set);
    Some((designated_document, rotated_document))
}

fn compromised_authority_documents(did: &str) -> Option<(DIDDocument, DIDDocument, DIDDocument)> {
    let (genesis, genesis_keys) = active_document(did)?;
    let (old_document, old_keys) = update_did(
        &genesis,
        &genesis_keys,
        UpdateConfig {
            services: None,
            also_known_as: None,
            hardware_bound: None,
            biometric_protected: None,
            user_verification_method: None,
            device_model: None,
            allowed: Some(vec!["#mldsa87-root".to_owned(), "#ed25519".to_owned()]),
            threshold: Some(1),
            deactivate: false,
            domain_verification: None,
            rotate_vms: None,
            authentication: None,
            assertion: None,
            invocation: Some(vec!["#mldsa87-root".to_owned(), "#ed25519".to_owned()]),
            key_agreement: None,
            created: Some("2026-01-02T00:00:00Z".to_owned()),
        },
    )
    .ok()?;
    let compromised = vec!["#ed25519".to_owned()];
    let (recovered_document, recovered_keys) = replace_compromised_keys(
        &old_document,
        &old_keys,
        &compromised,
        Some("2026-01-03T00:00:00Z".to_owned()),
    )
    .ok()?;
    let (unsafe_document, unsafe_keys) = rotate_keys(
        &old_document,
        &old_keys,
        &compromised,
        Some("2026-01-03T00:00:00Z".to_owned()),
    )
    .ok()?;
    drop(unsafe_keys);
    drop(recovered_keys);
    drop(old_keys);
    drop(genesis_keys);
    Some((old_document, recovered_document, unsafe_document))
}

#[test]
fn provider_mutation_commands_fail_closed_by_default() {
    let provider = ResolveOnlyProvider;

    let create_err = create_did_with_provider(&provider, DidCreateRequest::did_me()).unwrap_err();
    assert_eq!(create_err, DidApiError::ProviderCapabilityUnsupported);

    let Some((document, key_set)) = active_document("did:me:provider-closed-deactivate") else {
        return;
    };
    drop(key_set);
    let deactivate_err = deactivate_did_with_provider(
        &provider,
        DidDeactivateRequest {
            document: document.clone(),
        },
    )
    .unwrap_err();
    assert_eq!(deactivate_err, DidApiError::ProviderCapabilityUnsupported);

    let rotate_err = rotate_did_keys_with_provider(
        &provider,
        DidRotateSelectedKeysRequest {
            document: document.clone(),
            verification_method_ids: vec!["#ed25519".into()],
            created: Some("2026-01-02T00:00:00Z".to_owned()),
        },
    )
    .unwrap_err();
    assert_eq!(rotate_err, DidApiError::ProviderCapabilityUnsupported);

    let relationship_err = rotate_did_relationship_keys_with_provider(
        &provider,
        DidRotateRelationshipKeysDocumentRequest {
            document: document.clone(),
            relationship: RekeyRelationship::Authentication,
            created: Some("2026-01-02T00:00:00Z".to_owned()),
        },
    )
    .unwrap_err();
    assert_eq!(relationship_err, DidApiError::ProviderCapabilityUnsupported);

    let compromised_err = replace_compromised_did_keys_with_provider(
        &provider,
        DidReplaceCompromisedKeysRequest {
            document: document.clone(),
            compromised_verification_method_ids: vec!["#x25519".into()],
            created: Some("2026-01-02T00:00:00Z".to_owned()),
        },
    )
    .unwrap_err();
    assert_eq!(compromised_err, DidApiError::ProviderCapabilityUnsupported);

    let rotate_all_err = rotate_all_did_keys_with_provider(
        &provider,
        DidRotateAllDocumentKeysRequest {
            document: document.clone(),
            created: Some("2026-01-02T00:00:00Z".to_owned()),
        },
    )
    .unwrap_err();
    assert_eq!(rotate_all_err, DidApiError::ProviderCapabilityUnsupported);

    let relationships_err = set_did_key_relationships_with_provider(
        &provider,
        DidSetKeyRelationshipsDocumentRequest {
            document,
            authentication: Some(vec!["#mldsa87-root".to_owned()]),
            assertion_method: None,
            capability_invocation: None,
            key_agreement: None,
            threshold: None,
            created: Some("2026-01-02T00:00:00Z".to_owned()),
        },
    )
    .unwrap_err();
    assert_eq!(
        relationships_err,
        DidApiError::ProviderCapabilityUnsupported
    );

    let Some((document, _)) =
        messaging_designation_documents("did:me:provider-closed-messaging-designation")
    else {
        return;
    };
    let designation_err = designate_messaging_pre_keys_with_provider(
        &provider,
        DidDesignateMessagingPreKeysRequest {
            document,
            service_id: "#messaging".to_owned(),
            uri: "https://relay.example/inbox/subject".to_owned(),
            pre_keys: vec!["#x25519".to_owned(), "#mlkem768".to_owned()],
            created: Some("2026-01-02T00:00:00Z".to_owned()),
        },
    )
    .unwrap_err();
    assert_eq!(designation_err, DidApiError::ProviderCapabilityUnsupported);

    let Some((document, _)) =
        messaging_rotation_documents("did:me:provider-closed-messaging-rotation")
    else {
        return;
    };
    let rotation_err = rotate_messaging_pre_keys_with_provider(
        &provider,
        DidRotateMessagingPreKeysRequest {
            document,
            service_id: "#messaging".to_owned(),
            created: Some("2026-01-03T00:00:00Z".to_owned()),
        },
    )
    .unwrap_err();
    assert_eq!(rotation_err, DidApiError::ProviderCapabilityUnsupported);
}

#[test]
fn typed_deactivation_request_and_owned_result_are_validated_and_cleared() {
    let Some((old_document, key_set)) = active_document("did:me:provider-deactivate-owner") else {
        return;
    };
    let deactivated = deactivate_did(&old_document, &key_set);
    assert!(deactivated.is_ok());
    let (deactivated_document, deactivated_key_set) = match deactivated {
        Ok(value) => value,
        Err(_) => return,
    };
    drop(deactivated_key_set);
    drop(key_set);

    let provider = SuccessfulDeactivateProvider {
        document: deactivated_document,
    };
    let request = DidDeactivateRequest {
        document: old_document,
    };
    assert_eq!(format!("{request:?}"), "DidDeactivateRequest(<redacted>)");
    let owner = deactivate_did_with_provider_owned(&provider, request);
    assert!(owner.is_ok());
    let mut owner = match owner {
        Ok(owner) => owner,
        Err(_) => return,
    };
    assert_eq!(
        format!("{owner:?}"),
        "SensitiveDidDeactivatedDocument(<redacted>)"
    );
    assert!(owner.as_document().verification_method.is_empty());
    assert!(owner.as_document().service.is_empty());

    owner.zeroize();
    assert!(owner.as_document().id.is_empty());
    assert!(owner.as_document().attestations.is_empty());
}

#[test]
fn provider_deactivation_rejects_active_or_mutated_terminal_results() {
    let Some((old_document, key_set)) = active_document("did:me:provider-deactivate-invalid")
    else {
        return;
    };
    let deactivated = deactivate_did(&old_document, &key_set);
    assert!(deactivated.is_ok());
    let (mut terminal_document, terminal_key_set) = match deactivated {
        Ok(value) => value,
        Err(_) => return,
    };
    drop(terminal_key_set);
    drop(key_set);

    let active_provider = SuccessfulDeactivateProvider {
        document: old_document.clone(),
    };
    let active_result = deactivate_did_with_provider(
        &active_provider,
        DidDeactivateRequest {
            document: old_document.clone(),
        },
    );
    assert_eq!(active_result, Err(DidApiError::DeactivationResultInvalid));

    terminal_document.id = "did:me:provider-swapped-subject".into();
    let mutated_provider = SuccessfulDeactivateProvider {
        document: terminal_document,
    };
    let mutated_result = deactivate_did_with_provider(
        &mutated_provider,
        DidDeactivateRequest {
            document: old_document,
        },
    );
    assert_eq!(mutated_result, Err(DidApiError::DeactivationResultInvalid));
}

#[test]
fn provider_deactivation_rejects_terminal_input_before_provider_dispatch() {
    let Some((old_document, key_set)) = active_document("did:me:provider-deactivate-terminal")
    else {
        return;
    };
    let deactivated = deactivate_did(&old_document, &key_set);
    assert!(deactivated.is_ok());
    let (terminal_document, terminal_key_set) = match deactivated {
        Ok(value) => value,
        Err(_) => return,
    };
    drop(terminal_key_set);
    drop(key_set);

    let provider = SuccessfulDeactivateProvider {
        document: old_document,
    };
    let result = deactivate_did_with_provider(
        &provider,
        DidDeactivateRequest {
            document: terminal_document,
        },
    );
    assert_eq!(result, Err(DidApiError::DeactivationRequestInvalid));
}

#[test]
fn explicit_key_command_rejects_empty_selection_before_provider_dispatch() {
    let provider = ResolveOnlyProvider;
    let Some((document, key_set)) = active_document("did:me:provider-empty-rotation") else {
        return;
    };
    drop(key_set);

    let err = rotate_did_keys_with_provider(
        &provider,
        DidRotateSelectedKeysRequest {
            document,
            verification_method_ids: Vec::new(),
            created: None,
        },
    )
    .unwrap_err();

    assert_eq!(err, DidApiError::KeyRotationRequestInvalid);
}

#[test]
fn typed_selected_key_rotation_and_owned_result_are_validated_and_cleared() {
    let Some((old_document, rotated_document)) =
        selected_rotation_documents("did:me:provider-selected-rotation-owner")
    else {
        return;
    };
    let provider = SuccessfulRotateProvider {
        document: rotated_document,
    };
    let request = DidRotateSelectedKeysRequest {
        document: old_document,
        verification_method_ids: vec!["#ed25519".to_owned()],
        created: Some("2026-01-02T00:00:00Z".to_owned()),
    };
    assert_eq!(
        format!("{request:?}"),
        "DidRotateSelectedKeysRequest(<redacted>)"
    );
    let owner = rotate_did_keys_with_provider_owned(&provider, request);
    assert!(owner.is_ok());
    let mut owner = match owner {
        Ok(owner) => owner,
        Err(_) => return,
    };
    assert_eq!(
        format!("{owner:?}"),
        "SensitiveDidRotatedDocument(<redacted>)"
    );
    assert!(!owner.as_document().verification_method.is_empty());

    owner.zeroize();
    assert!(owner.as_document().id.is_empty());
    assert!(owner.as_document().verification_method.is_empty());
}

#[test]
fn selected_key_rotation_rejects_malformed_selection_before_provider_dispatch() {
    let Some((old_document, rotated_document)) =
        selected_rotation_documents("did:me:provider-selected-rotation-invalid-request")
    else {
        return;
    };
    let cases = [
        (vec!["#ed25519".to_owned(), "#ed25519".to_owned()], None),
        (vec!["#missing".to_owned()], None),
        (vec!["#ed25519".to_owned()], Some("not-rfc3339".to_owned())),
    ];

    for (verification_method_ids, created) in cases {
        let provider = SuccessfulRotateProvider {
            document: rotated_document.clone(),
        };
        let result = rotate_did_keys_with_provider(
            &provider,
            DidRotateSelectedKeysRequest {
                document: old_document.clone(),
                verification_method_ids,
                created,
            },
        );
        assert_eq!(result, Err(DidApiError::KeyRotationRequestInvalid));
    }
}

#[test]
fn selected_key_rotation_rejects_wrong_key_or_projection_changes() {
    let Some((old_document, rotated_document)) =
        selected_rotation_documents("did:me:provider-selected-rotation-invalid-result")
    else {
        return;
    };

    let unchanged_provider = SuccessfulRotateProvider {
        document: old_document.clone(),
    };
    let unchanged = rotate_did_keys_with_provider(
        &unchanged_provider,
        DidRotateSelectedKeysRequest {
            document: old_document.clone(),
            verification_method_ids: vec!["#ed25519".to_owned()],
            created: Some("2026-01-02T00:00:00Z".to_owned()),
        },
    );
    assert_eq!(unchanged, Err(DidApiError::KeyRotationResultInvalid));

    let mut mutated = rotated_document;
    mutated
        .also_known_as
        .push("https://private.example/subject".to_owned());
    let mutated_provider = SuccessfulRotateProvider { document: mutated };
    let mutated = rotate_did_keys_with_provider(
        &mutated_provider,
        DidRotateSelectedKeysRequest {
            document: old_document,
            verification_method_ids: vec!["#ed25519".to_owned()],
            created: Some("2026-01-02T00:00:00Z".to_owned()),
        },
    );
    assert_eq!(mutated, Err(DidApiError::KeyRotationResultInvalid));
}

#[test]
fn relationship_key_rotation_validates_complete_selection_and_owned_result() {
    let Some((old_document, rotated_document)) =
        relationship_rotation_documents("did:me:provider-relationship-rotation-owner")
    else {
        return;
    };
    let provider = SuccessfulRotateProvider {
        document: rotated_document,
    };
    let request = DidRotateRelationshipKeysDocumentRequest {
        document: old_document,
        relationship: RekeyRelationship::Authentication,
        created: Some("2026-01-02T00:00:00Z".to_owned()),
    };
    assert_eq!(
        format!("{request:?}"),
        "DidRotateRelationshipKeysDocumentRequest(<redacted>)"
    );
    let owner = rotate_did_relationship_keys_with_provider_owned(&provider, request);
    assert!(owner.is_ok());
    let mut owner = match owner {
        Ok(owner) => owner,
        Err(_) => return,
    };
    assert!(!owner.as_document().authentication.is_empty());
    owner.zeroize();
    assert!(owner.as_document().id.is_empty());
}
