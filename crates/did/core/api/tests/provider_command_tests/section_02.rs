// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#[test]
fn relationship_key_rotation_rejects_unsupported_empty_and_malformed_requests() {
    let Some((old_document, rotated_document)) =
        relationship_rotation_documents("did:me:provider-relationship-invalid-request")
    else {
        return;
    };
    let provider = SuccessfulRotateProvider {
        document: rotated_document,
    };

    for relationship in [
        RekeyRelationship::Assertion,
        RekeyRelationship::CapabilityDelegation,
        RekeyRelationship::Controller,
    ] {
        let result = rotate_did_relationship_keys_with_provider(
            &provider,
            DidRotateRelationshipKeysDocumentRequest {
                document: old_document.clone(),
                relationship,
                created: Some("2026-01-02T00:00:00Z".to_owned()),
            },
        );
        assert_eq!(
            result,
            Err(DidApiError::RelationshipKeyRotationRequestInvalid)
        );
    }

    let mut empty_relationship = old_document.clone();
    empty_relationship.authentication.clear();
    let empty = rotate_did_relationship_keys_with_provider(
        &provider,
        DidRotateRelationshipKeysDocumentRequest {
            document: empty_relationship,
            relationship: RekeyRelationship::Authentication,
            created: Some("2026-01-02T00:00:00Z".to_owned()),
        },
    );
    assert_eq!(
        empty,
        Err(DidApiError::RelationshipKeyRotationRequestInvalid)
    );

    let malformed_timestamp = rotate_did_relationship_keys_with_provider(
        &provider,
        DidRotateRelationshipKeysDocumentRequest {
            document: old_document,
            relationship: RekeyRelationship::Authentication,
            created: Some("not-rfc3339".to_owned()),
        },
    );
    assert_eq!(
        malformed_timestamp,
        Err(DidApiError::RelationshipKeyRotationRequestInvalid)
    );
}

#[test]
fn relationship_key_rotation_rejects_unselected_and_projection_mutation() {
    let Some((old_document, rotated_document)) =
        relationship_rotation_documents("did:me:provider-relationship-invalid-result")
    else {
        return;
    };
    let mut unselected_changed = rotated_document.clone();
    let unselected = unselected_changed
        .verification_method
        .iter_mut()
        .find(|method| method.id == "#x25519");
    if let Some(method) = unselected {
        method.public_key_multibase.push('x');
    } else {
        return;
    }
    let provider = SuccessfulRotateProvider {
        document: unselected_changed,
    };
    let result = rotate_did_relationship_keys_with_provider(
        &provider,
        DidRotateRelationshipKeysDocumentRequest {
            document: old_document.clone(),
            relationship: RekeyRelationship::Authentication,
            created: Some("2026-01-02T00:00:00Z".to_owned()),
        },
    );
    assert_eq!(
        result,
        Err(DidApiError::RelationshipKeyRotationResultInvalid)
    );

    let mut projection_changed = rotated_document;
    projection_changed.key_agreement.clear();
    let provider = SuccessfulRotateProvider {
        document: projection_changed,
    };
    let result = rotate_did_relationship_keys_with_provider(
        &provider,
        DidRotateRelationshipKeysDocumentRequest {
            document: old_document,
            relationship: RekeyRelationship::Authentication,
            created: Some("2026-01-02T00:00:00Z".to_owned()),
        },
    );
    assert_eq!(
        result,
        Err(DidApiError::RelationshipKeyRotationResultInvalid)
    );
}

#[test]
fn compromised_key_replacement_validates_recovery_and_owned_result() {
    let Some((old_document, replaced_document)) =
        compromised_key_replacement_documents("did:me:provider-compromised-owner")
    else {
        return;
    };
    let provider = SuccessfulRotateProvider {
        document: replaced_document,
    };
    let request = DidReplaceCompromisedKeysRequest {
        document: old_document,
        compromised_verification_method_ids: vec!["#x25519".to_owned()],
        created: Some("2026-01-02T00:00:00Z".to_owned()),
    };
    assert_eq!(
        format!("{request:?}"),
        "DidReplaceCompromisedKeysRequest(<redacted>)"
    );
    let owner = replace_compromised_did_keys_with_provider_owned(&provider, request);
    assert!(owner.is_ok());
    let mut owner = match owner {
        Ok(owner) => owner,
        Err(_) => return,
    };
    assert!(!owner.as_document().attestations.is_empty());
    owner.zeroize();
    assert!(owner.as_document().id.is_empty());
}

#[test]
fn compromised_key_replacement_rejects_malformed_or_unauthorized_requests() {
    let Some((old_document, replaced_document)) =
        compromised_key_replacement_documents("did:me:provider-compromised-invalid-request")
    else {
        return;
    };
    let provider = SuccessfulRotateProvider {
        document: replaced_document,
    };
    let cases = [
        (Vec::new(), Some("2026-01-02T00:00:00Z".to_owned())),
        (
            vec!["#x25519".to_owned(), "#x25519".to_owned()],
            Some("2026-01-02T00:00:00Z".to_owned()),
        ),
        (
            vec!["#missing".to_owned()],
            Some("2026-01-02T00:00:00Z".to_owned()),
        ),
        (vec!["#x25519".to_owned()], Some("not-rfc3339".to_owned())),
    ];
    for (compromised_verification_method_ids, created) in cases {
        let result = replace_compromised_did_keys_with_provider(
            &provider,
            DidReplaceCompromisedKeysRequest {
                document: old_document.clone(),
                compromised_verification_method_ids,
                created,
            },
        );
        assert_eq!(
            result,
            Err(DidApiError::CompromisedKeyReplacementRequestInvalid)
        );
    }

    let unsatisfied = replace_compromised_did_keys_with_provider(
        &provider,
        DidReplaceCompromisedKeysRequest {
            document: old_document,
            compromised_verification_method_ids: vec!["#ed25519".to_owned()],
            created: Some("2026-01-02T00:00:00Z".to_owned()),
        },
    );
    assert_eq!(
        unsatisfied,
        Err(DidApiError::CompromisedKeyReplacementRequestInvalid)
    );
}

#[test]
fn compromised_key_replacement_rejects_compromised_authorization_and_substitution() {
    let Some((old_document, recovered_document, unsafe_document)) =
        compromised_authority_documents("did:me:provider-compromised-authority")
    else {
        return;
    };
    assert!(unsafe_document
        .attestations
        .iter()
        .any(|attestation| attestation.vm == "#ed25519"));
    assert!(!recovered_document
        .attestations
        .iter()
        .any(|attestation| attestation.vm == "#ed25519"));

    let provider = SuccessfulRotateProvider {
        document: unsafe_document,
    };
    let result = replace_compromised_did_keys_with_provider(
        &provider,
        DidReplaceCompromisedKeysRequest {
            document: old_document.clone(),
            compromised_verification_method_ids: vec!["#ed25519".to_owned()],
            created: Some("2026-01-03T00:00:00Z".to_owned()),
        },
    );
    assert_eq!(
        result,
        Err(DidApiError::CompromisedKeyReplacementResultInvalid)
    );

    let mut substituted = recovered_document;
    substituted
        .also_known_as
        .push("https://private.example".to_owned());
    let provider = SuccessfulRotateProvider {
        document: substituted,
    };
    let result = replace_compromised_did_keys_with_provider(
        &provider,
        DidReplaceCompromisedKeysRequest {
            document: old_document,
            compromised_verification_method_ids: vec!["#ed25519".to_owned()],
            created: Some("2026-01-03T00:00:00Z".to_owned()),
        },
    );
    assert_eq!(
        result,
        Err(DidApiError::CompromisedKeyReplacementResultInvalid)
    );
}

#[test]
fn all_key_rotation_derives_the_complete_set_and_clears_owned_results() {
    let Some((old_document, rotated_document)) =
        all_key_rotation_documents("did:me:provider-all-key-rotation-owner")
    else {
        return;
    };
    assert_eq!(
        old_document.verification_method.len(),
        rotated_document.verification_method.len()
    );
    for (old_method, rotated_method) in old_document
        .verification_method
        .iter()
        .zip(&rotated_document.verification_method)
    {
        assert_eq!(old_method.id, rotated_method.id);
        assert_ne!(
            old_method.public_key_multibase,
            rotated_method.public_key_multibase
        );
    }

    let provider = SuccessfulRotateProvider {
        document: rotated_document,
    };
    let request = DidRotateAllDocumentKeysRequest {
        document: old_document,
        created: Some("2026-01-02T00:00:00Z".to_owned()),
    };
    assert_eq!(
        format!("{request:?}"),
        "DidRotateAllDocumentKeysRequest(<redacted>)"
    );
    let owner = rotate_all_did_keys_with_provider_owned(&provider, request);
    assert!(owner.is_ok());
    let mut owner = match owner {
        Ok(owner) => owner,
        Err(_) => return,
    };
    assert!(!owner.as_document().verification_method.is_empty());
    owner.zeroize();
    assert!(owner.as_document().id.is_empty());
    assert!(owner.as_document().verification_method.is_empty());
}

#[test]
fn all_key_rotation_rejects_malformed_authoritative_requests() {
    let Some((old_document, rotated_document)) =
        all_key_rotation_documents("did:me:provider-all-key-invalid-request")
    else {
        return;
    };
    let provider = SuccessfulRotateProvider {
        document: rotated_document,
    };

    let mut no_methods = old_document.clone();
    no_methods.verification_method.clear();
    let cases = [
        DidRotateAllDocumentKeysRequest {
            document: no_methods,
            created: Some("2026-01-02T00:00:00Z".to_owned()),
        },
        DidRotateAllDocumentKeysRequest {
            document: old_document,
            created: Some("not-rfc3339".to_owned()),
        },
    ];
    for request in cases {
        assert_eq!(
            rotate_all_did_keys_with_provider(&provider, request),
            Err(DidApiError::AllKeyRotationRequestInvalid)
        );
    }
}

#[test]
fn all_key_rotation_rejects_partial_rotation_and_projection_substitution() {
    let Some((old_document, rotated_document)) =
        all_key_rotation_documents("did:me:provider-all-key-invalid-result")
    else {
        return;
    };
    let Some(old_first_method) = old_document.verification_method.first() else {
        return;
    };

    let mut partial_rotation = rotated_document.clone();
    let Some(rotated_first_method) = partial_rotation.verification_method.first_mut() else {
        return;
    };
    rotated_first_method.public_key_multibase = old_first_method.public_key_multibase.clone();
    let provider = SuccessfulRotateProvider {
        document: partial_rotation,
    };
    let request = DidRotateAllDocumentKeysRequest {
        document: old_document.clone(),
        created: Some("2026-01-02T00:00:00Z".to_owned()),
    };
    assert_eq!(
        rotate_all_did_keys_with_provider(&provider, request),
        Err(DidApiError::AllKeyRotationResultInvalid)
    );

    let mut substituted = rotated_document;
    substituted
        .also_known_as
        .push("https://private.example/subject".to_owned());
    let provider = SuccessfulRotateProvider {
        document: substituted,
    };
    let request = DidRotateAllDocumentKeysRequest {
        document: old_document,
        created: Some("2026-01-02T00:00:00Z".to_owned()),
    };
    assert_eq!(
        rotate_all_did_keys_with_provider(&provider, request),
        Err(DidApiError::AllKeyRotationResultInvalid)
    );
}

#[test]
fn key_relationship_assignment_preserves_keys_and_clears_owned_results() {
    let Some((old_document, assigned_document)) =
        relationship_assignment_documents("did:me:provider-relationship-assignment-owner")
    else {
        return;
    };
    assert_eq!(
        old_document.verification_method,
        assigned_document.verification_method
    );
    assert_eq!(assigned_document.authentication, vec!["#mldsa87-root"]);
    assert_eq!(
        assigned_document.assertion_method,
        old_document.assertion_method
    );
    assert_eq!(
        assigned_document.capability_invocation,
        old_document.capability_invocation
    );
    assert_eq!(assigned_document.key_agreement, old_document.key_agreement);
    assert_eq!(assigned_document.update_policy, old_document.update_policy);
    assert_eq!(assigned_document.service, old_document.service);
    assert_eq!(assigned_document.also_known_as, old_document.also_known_as);
    assert_eq!(
        assigned_document.hardware_bound,
        old_document.hardware_bound
    );
    assert_eq!(
        assigned_document.data_integrity_proof.is_some(),
        old_document.data_integrity_proof.is_some()
    );
    assert!(!assigned_document.attestations.is_empty());
    let provider = SuccessfulRotateProvider {
        document: assigned_document,
    };
    let request = DidSetKeyRelationshipsDocumentRequest {
        document: old_document,
        authentication: Some(vec!["#mldsa87-root".to_owned()]),
        assertion_method: None,
        capability_invocation: None,
        key_agreement: None,
        threshold: None,
        created: Some("2026-01-02T00:00:00Z".to_owned()),
    };
    assert_eq!(
        format!("{request:?}"),
        "DidSetKeyRelationshipsDocumentRequest(<redacted>)"
    );
    let owner = set_did_key_relationships_with_provider_owned(&provider, request);
    assert!(owner.is_ok(), "{:?}", owner.as_ref().err());
    let mut owner = match owner {
        Ok(owner) => owner,
        Err(_) => return,
    };
    assert_eq!(owner.as_document().authentication, vec!["#mldsa87-root"]);
    owner.zeroize();
    assert!(owner.as_document().id.is_empty());
    assert!(owner.as_document().verification_method.is_empty());
}

#[test]
fn key_relationship_assignment_rejects_malformed_or_incompatible_requests() {
    let Some((old_document, assigned_document)) =
        relationship_assignment_documents("did:me:provider-relationship-assignment-invalid")
    else {
        return;
    };
    let provider = SuccessfulRotateProvider {
        document: assigned_document,
    };
    let cases = [
        DidSetKeyRelationshipsDocumentRequest {
            document: old_document.clone(),
            authentication: None,
            assertion_method: None,
            capability_invocation: None,
            key_agreement: None,
            threshold: None,
            created: Some("2026-01-02T00:00:00Z".to_owned()),
        },
        DidSetKeyRelationshipsDocumentRequest {
            document: old_document.clone(),
            authentication: Some(vec!["#ed25519".to_owned(), "#ed25519".to_owned()]),
            assertion_method: None,
            capability_invocation: None,
            key_agreement: None,
            threshold: None,
            created: Some("2026-01-02T00:00:00Z".to_owned()),
        },
        DidSetKeyRelationshipsDocumentRequest {
            document: old_document.clone(),
            authentication: Some(vec!["#x25519".to_owned()]),
            assertion_method: None,
            capability_invocation: None,
            key_agreement: None,
            threshold: None,
            created: Some("2026-01-02T00:00:00Z".to_owned()),
        },
        DidSetKeyRelationshipsDocumentRequest {
            document: old_document.clone(),
            authentication: None,
            assertion_method: Some(vec!["#ed25519".to_owned()]),
            capability_invocation: None,
            key_agreement: None,
            threshold: None,
            created: Some("2026-01-02T00:00:00Z".to_owned()),
        },
        DidSetKeyRelationshipsDocumentRequest {
            document: old_document.clone(),
            authentication: Some(vec!["#mldsa87-root".to_owned()]),
            assertion_method: None,
            capability_invocation: None,
            key_agreement: None,
            threshold: Some(1),
            created: Some("2026-01-02T00:00:00Z".to_owned()),
        },
        DidSetKeyRelationshipsDocumentRequest {
            document: old_document,
            authentication: Some(vec!["#mldsa87-root".to_owned()]),
            assertion_method: None,
            capability_invocation: None,
            key_agreement: None,
            threshold: None,
            created: Some("not-rfc3339".to_owned()),
        },
    ];
    for request in cases {
        assert_eq!(
            set_did_key_relationships_with_provider(&provider, request),
            Err(DidApiError::KeyRelationshipAssignmentRequestInvalid)
        );
    }
}

#[test]
fn key_relationship_assignment_rejects_key_and_projection_substitution() {
    let Some((old_document, assigned_document)) =
        relationship_assignment_documents("did:me:provider-relationship-assignment-result")
    else {
        return;
    };
    let mut key_changed = assigned_document.clone();
    let Some(method) = key_changed.verification_method.first_mut() else {
        return;
    };
    method.public_key_multibase.push('x');
    let provider = SuccessfulRotateProvider {
        document: key_changed,
    };
    let request = DidSetKeyRelationshipsDocumentRequest {
        document: old_document.clone(),
        authentication: Some(vec!["#mldsa87-root".to_owned()]),
        assertion_method: None,
        capability_invocation: None,
        key_agreement: None,
        threshold: None,
        created: Some("2026-01-02T00:00:00Z".to_owned()),
    };
    assert_eq!(
        set_did_key_relationships_with_provider(&provider, request),
        Err(DidApiError::KeyRelationshipAssignmentResultInvalid)
    );

    let mut substituted = assigned_document;
    substituted
        .also_known_as
        .push("https://private.example/subject".to_owned());
    let provider = SuccessfulRotateProvider {
        document: substituted,
    };
    let request = DidSetKeyRelationshipsDocumentRequest {
        document: old_document,
        authentication: Some(vec!["#mldsa87-root".to_owned()]),
        assertion_method: None,
        capability_invocation: None,
        key_agreement: None,
        threshold: None,
        created: Some("2026-01-02T00:00:00Z".to_owned()),
    };
    assert_eq!(
        set_did_key_relationships_with_provider(&provider, request),
        Err(DidApiError::KeyRelationshipAssignmentResultInvalid)
    );
}

#[test]
fn messaging_pre_key_designation_validates_exact_transition_and_clears_owned_result() {
    let Some((old_document, designated_document)) =
        messaging_designation_documents("did:me:provider-messaging-designation-owner")
    else {
        return;
    };
    let provider = SuccessfulRotateProvider {
        document: designated_document,
    };
    let request = DidDesignateMessagingPreKeysRequest {
        document: old_document,
        service_id: "#messaging".to_owned(),
        uri: "https://relay.example/inbox/subject".to_owned(),
        pre_keys: vec!["#x25519".to_owned(), "#mlkem768".to_owned()],
        created: Some("2026-01-02T00:00:00Z".to_owned()),
    };
    assert_eq!(
        format!("{request:?}"),
        "DidDesignateMessagingPreKeysRequest(<redacted>)"
    );
    let owner = designate_messaging_pre_keys_with_provider_owned(&provider, request);
    assert!(owner.is_ok());
    let mut owner = match owner {
        Ok(owner) => owner,
        Err(_) => return,
    };
    assert_eq!(owner.as_document().service.len(), 1);
    assert_eq!(owner.as_document().service[0].id, "#messaging");
    owner.zeroize();
    assert!(owner.as_document().id.is_empty());
    assert!(owner.as_document().service.is_empty());
}

#[test]
fn messaging_pre_key_designation_rejects_malformed_or_incompatible_requests() {
    let Some((old_document, designated_document)) =
        messaging_designation_documents("did:me:provider-messaging-designation-invalid-request")
    else {
        return;
    };
    let provider = SuccessfulRotateProvider {
        document: designated_document,
    };
    let cases = [
        DidDesignateMessagingPreKeysRequest {
            document: old_document.clone(),
            service_id: "#messaging".to_owned(),
            uri: "https://relay.example/inbox/subject".to_owned(),
            pre_keys: vec!["#x25519".to_owned()],
            created: Some("2026-01-02T00:00:00Z".to_owned()),
        },
        DidDesignateMessagingPreKeysRequest {
            document: old_document.clone(),
            service_id: "#messaging".to_owned(),
            uri: "https://relay.example/inbox/subject".to_owned(),
            pre_keys: vec!["#x25519".to_owned(), "#x25519".to_owned()],
            created: Some("2026-01-02T00:00:00Z".to_owned()),
        },
        DidDesignateMessagingPreKeysRequest {
            document: old_document.clone(),
            service_id: "#messaging".to_owned(),
            uri: "https://relay.example/inbox/subject".to_owned(),
            pre_keys: vec!["#x25519".to_owned(), "#mlkem768".to_owned()],
            created: None,
        },
        DidDesignateMessagingPreKeysRequest {
            document: old_document,
            service_id: "#messaging".to_owned(),
            uri: "https://relay.example/inbox/subject".to_owned(),
            pre_keys: vec!["#x25519".to_owned(), "#mlkem768".to_owned()],
            created: Some("not-rfc3339".to_owned()),
        },
    ];
    for request in cases {
        assert_eq!(
            designate_messaging_pre_keys_with_provider(&provider, request),
            Err(DidApiError::MessagingPreKeyDesignationInvalid)
        );
    }
}

#[test]
fn messaging_pre_key_designation_rejects_provider_substitution() {
    let Some((old_document, designated_document)) =
        messaging_designation_documents("did:me:provider-messaging-designation-substitution")
    else {
        return;
    };
    let mut substituted = designated_document;
    substituted
        .also_known_as
        .push("https://private.example/subject".to_owned());
    let provider = SuccessfulRotateProvider {
        document: substituted,
    };
    let result = designate_messaging_pre_keys_with_provider(
        &provider,
        DidDesignateMessagingPreKeysRequest {
            document: old_document,
            service_id: "#messaging".to_owned(),
            uri: "https://relay.example/inbox/subject".to_owned(),
            pre_keys: vec!["#x25519".to_owned(), "#mlkem768".to_owned()],
            created: Some("2026-01-02T00:00:00Z".to_owned()),
        },
    );
    assert_eq!(result, Err(DidApiError::MessagingPreKeyDesignationInvalid));
}

#[test]
fn messaging_pre_key_rotation_validates_exact_transition_and_clears_owned_result() {
    let Some((old_document, rotated_document)) =
        messaging_rotation_documents("did:me:provider-messaging-rotation-owner")
    else {
        return;
    };
    for old_method in &old_document.verification_method {
        let Some(rotated_method) = rotated_document
            .verification_method
            .iter()
            .find(|candidate| candidate.id == old_method.id)
        else {
            return;
        };
        if matches!(old_method.id.as_str(), "#x25519" | "#mlkem768") {
            assert_ne!(
                old_method.public_key_multibase,
                rotated_method.public_key_multibase
            );
        } else {
            assert_eq!(old_method, rotated_method);
        }
    }

    let provider = SuccessfulRotateProvider {
        document: rotated_document,
    };
    let request = DidRotateMessagingPreKeysRequest {
        document: old_document,
        service_id: "#messaging".to_owned(),
        created: Some("2026-01-03T00:00:00Z".to_owned()),
    };
    assert_eq!(
        format!("{request:?}"),
        "DidRotateMessagingPreKeysRequest(<redacted>)"
    );
    let owner = rotate_messaging_pre_keys_with_provider_owned(&provider, request);
    assert!(owner.is_ok());
    let mut owner = match owner {
        Ok(owner) => owner,
        Err(_) => return,
    };
    assert_eq!(owner.as_document().service.len(), 1);
    owner.zeroize();
    assert!(owner.as_document().id.is_empty());
    assert!(owner.as_document().verification_method.is_empty());
    assert!(owner.as_document().service.is_empty());
}
