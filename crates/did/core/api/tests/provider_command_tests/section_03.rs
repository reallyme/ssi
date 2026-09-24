// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#[test]
fn messaging_pre_key_rotation_rejects_malformed_or_incompatible_requests() {
    let Some((old_document, rotated_document)) =
        messaging_rotation_documents("did:me:provider-messaging-rotation-invalid-request")
    else {
        return;
    };
    let provider = SuccessfulRotateProvider {
        document: rotated_document,
    };
    let cases = [
        DidRotateMessagingPreKeysRequest {
            document: old_document.clone(),
            service_id: "#missing".to_owned(),
            created: Some("2026-01-03T00:00:00Z".to_owned()),
        },
        DidRotateMessagingPreKeysRequest {
            document: old_document.clone(),
            service_id: String::new(),
            created: Some("2026-01-03T00:00:00Z".to_owned()),
        },
        DidRotateMessagingPreKeysRequest {
            document: old_document.clone(),
            service_id: "#messaging".to_owned(),
            created: None,
        },
        DidRotateMessagingPreKeysRequest {
            document: old_document,
            service_id: "#messaging".to_owned(),
            created: Some("not-rfc3339".to_owned()),
        },
    ];
    for request in cases {
        assert_eq!(
            rotate_messaging_pre_keys_with_provider(&provider, request),
            Err(DidApiError::MessagingPreKeyRotationInvalid)
        );
    }
}

#[test]
fn messaging_pre_key_rotation_rejects_partial_rotation_and_provider_substitution() {
    let Some((old_document, rotated_document)) =
        messaging_rotation_documents("did:me:provider-messaging-rotation-substitution")
    else {
        return;
    };
    let Some(old_x25519) = old_document
        .verification_method
        .iter()
        .find(|method| method.id == "#x25519")
    else {
        return;
    };
    let mut partial_rotation = rotated_document.clone();
    let Some(rotated_x25519) = partial_rotation
        .verification_method
        .iter_mut()
        .find(|method| method.id == "#x25519")
    else {
        return;
    };
    rotated_x25519.public_key_multibase = old_x25519.public_key_multibase.clone();
    let request = DidRotateMessagingPreKeysRequest {
        document: old_document.clone(),
        service_id: "#messaging".to_owned(),
        created: Some("2026-01-03T00:00:00Z".to_owned()),
    };
    let provider = SuccessfulRotateProvider {
        document: partial_rotation,
    };
    assert_eq!(
        rotate_messaging_pre_keys_with_provider(&provider, request),
        Err(DidApiError::MessagingPreKeyRotationInvalid)
    );

    let mut substituted = rotated_document;
    substituted
        .also_known_as
        .push("https://private.example/subject".to_owned());
    let provider = SuccessfulRotateProvider {
        document: substituted,
    };
    let request = DidRotateMessagingPreKeysRequest {
        document: old_document,
        service_id: "#messaging".to_owned(),
        created: Some("2026-01-03T00:00:00Z".to_owned()),
    };
    assert_eq!(
        rotate_messaging_pre_keys_with_provider(&provider, request),
        Err(DidApiError::MessagingPreKeyRotationInvalid)
    );
}

#[test]
fn create_request_uses_closed_method_enum() {
    let request = DidCreateRequest::did_me();
    assert_eq!(request.method, DidMethod::DidMe);
    assert_eq!(request.profile, None);
}

#[test]
fn typed_create_profile_and_owned_result_are_validated_and_cleared() {
    let request = DidCreateRequest {
        method: DidMethod::DidMe,
        profile: Some(DidProfile::Messaging),
    };
    assert_eq!(request.method, DidMethod::DidMe);
    assert_eq!(request.profile, Some(DidProfile::Messaging));

    let created = create_did(
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
        "did:me:provider-create-owner",
    );
    assert!(created.is_ok());
    let (document, _) = match created {
        Ok(created) => created,
        Err(_) => return,
    };
    let provider = SuccessfulCreateProvider { document };
    let owner = create_did_with_provider_owned(&provider, DidCreateRequest::did_me());
    assert!(owner.is_ok());
    let mut owner = match owner {
        Ok(owner) => owner,
        Err(_) => return,
    };
    assert_eq!(
        format!("{owner:?}"),
        "SensitiveDidCreatedDocument(<redacted>)"
    );

    owner.zeroize();

    assert!(owner.as_document().id.is_empty());
    assert!(owner.as_document().verification_method.is_empty());
}

#[test]
fn typed_update_request_and_owned_result_are_validated_and_cleared() {
    let created = create_did(
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
        "did:me:provider-update-owner",
    );
    assert!(created.is_ok());
    let (old_document, key_set) = match created {
        Ok(created) => created,
        Err(_) => return,
    };
    let alias = "https://identity.example/subject".to_owned();
    let updated = update_did(
        &old_document,
        &key_set,
        UpdateConfig {
            services: None,
            also_known_as: Some(vec![alias.clone()]),
            hardware_bound: Some(true),
            biometric_protected: None,
            user_verification_method: None,
            device_model: Some("secure-device".into()),
            allowed: None,
            threshold: None,
            deactivate: false,
            domain_verification: None,
            rotate_vms: None,
            authentication: None,
            assertion: None,
            invocation: None,
            key_agreement: None,
            created: Some("2026-01-02T00:00:00Z".into()),
        },
    );
    assert!(updated.is_ok());
    let (updated_document, updated_key_set) = match updated {
        Ok(updated) => updated,
        Err(_) => return,
    };
    drop(updated_key_set);
    drop(key_set);

    let provider = SuccessfulUpdateProvider {
        document: updated_document,
    };
    let request = DidUpdateRequest {
        document: old_document,
        services: None,
        also_known_as: Some(vec![alias]),
        hardware_bound: Some(DidBoolPropertyUpdate::Set(true)),
        biometric_protected: None,
        user_verification_method: None,
        device_model: Some(DidStringPropertyUpdate::Set("secure-device".into())),
        domain_verification: None,
    };
    assert_eq!(format!("{request:?}"), "DidUpdateRequest(<redacted>)");
    let owner = update_did_with_provider_owned(&provider, request);
    assert!(owner.is_ok());
    let mut owner = match owner {
        Ok(owner) => owner,
        Err(_) => return,
    };
    assert_eq!(
        format!("{owner:?}"),
        "SensitiveDidUpdatedDocument(<redacted>)"
    );

    owner.zeroize();

    assert!(owner.as_document().id.is_empty());
    assert!(owner.as_document().verification_method.is_empty());
}

#[test]
fn provider_update_rejects_a_non_transitioning_result() {
    let created = create_did(
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
        "did:me:provider-update-invalid",
    );
    assert!(created.is_ok());
    let (old_document, key_set) = match created {
        Ok(created) => created,
        Err(_) => return,
    };
    drop(key_set);
    let provider = SuccessfulUpdateProvider {
        document: old_document.clone(),
    };
    let result = update_did_with_provider(
        &provider,
        DidUpdateRequest {
            document: old_document,
            services: None,
            also_known_as: None,
            hardware_bound: None,
            biometric_protected: None,
            user_verification_method: None,
            device_model: None,
            domain_verification: None,
        },
    );

    assert_eq!(result, Err(DidApiError::UpdateResultInvalid));
}

#[test]
fn provider_update_rejects_malformed_patch_before_result_validation() {
    let created = create_did(
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
        "did:me:provider-update-malformed-patch",
    );
    assert!(created.is_ok());
    let (old_document, key_set) = match created {
        Ok(created) => created,
        Err(_) => return,
    };
    drop(key_set);
    let provider = SuccessfulUpdateProvider {
        document: old_document.clone(),
    };
    let result = update_did_with_provider(
        &provider,
        DidUpdateRequest {
            document: old_document,
            services: Some(vec![Service {
                id: "#invalid-null-endpoint".into(),
                service_type: "LinkedDomains".into(),
                service_endpoint: serde_json::Value::Null,
            }]),
            also_known_as: None,
            hardware_bound: None,
            biometric_protected: None,
            user_verification_method: None,
            device_model: None,
            domain_verification: None,
        },
    );

    assert_eq!(result, Err(DidApiError::UpdateRequestInvalid));
}
