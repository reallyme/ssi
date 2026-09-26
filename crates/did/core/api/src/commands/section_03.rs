// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

fn validate_updated_document(
    request: &DidUpdateRequest,
    document: &DIDDocument,
) -> Result<(), DidApiError> {
    let old = &request.document;
    let expected_sequence = old
        .sequence
        .checked_add(1)
        .ok_or(DidApiError::UpdateResultInvalid)?;
    let expected_history_len = old
        .key_history
        .len()
        .checked_add(1)
        .ok_or(DidApiError::UpdateResultInvalid)?;

    let history_is_valid = document.key_history.len() == expected_history_len
        && document
            .key_history
            .get(..old.key_history.len())
            .is_some_and(|history| history == old.key_history.as_slice())
        && document.key_history.last() == Some(&old.current_core);
    let immutable_projection_is_valid = document.id == old.id
        && document.controller == old.controller
        && document.context == old.context
        && document.verification_method == old.verification_method
        && document.authentication == old.authentication
        && document.assertion_method == old.assertion_method
        && document.capability_invocation == old.capability_invocation
        && document.key_agreement == old.key_agreement
        && document.update_policy == old.update_policy
        && document.eudi_level_of_assurance == old.eudi_level_of_assurance
        && document.eudi_schema_version == old.eudi_schema_version;
    let expected_services = request.services.as_deref().unwrap_or(&old.service);
    let expected_also_known_as = request
        .also_known_as
        .as_deref()
        .unwrap_or(&old.also_known_as);
    let expected_domain_verification = Zeroizing::new(
        merge_domain_verification(
            &old.id,
            &old.domain_verification,
            request.domain_verification.as_deref(),
        )
        .map_err(|_| DidApiError::UpdateResultInvalid)?,
    );

    if document.sequence != expected_sequence
        || document.prev.as_ref() != Some(&old.current_core)
        || document.current_core == old.current_core
        || document.nonce.is_some()
        || !history_is_valid
        || !immutable_projection_is_valid
        || document.service != expected_services
        || document.also_known_as != expected_also_known_as
        || document.hardware_bound
            != expected_bool_property(request.hardware_bound, old.hardware_bound)
        || document.biometric_protected
            != expected_bool_property(request.biometric_protected, old.biometric_protected)
        || document.user_verification_method.as_deref()
            != expected_string_property(
                request.user_verification_method.as_ref(),
                old.user_verification_method.as_deref(),
            )
        || document.device_model.as_deref()
            != expected_string_property(request.device_model.as_ref(), old.device_model.as_deref())
        || document.domain_verification.as_slice() != expected_domain_verification.as_slice()
    {
        return Err(DidApiError::UpdateResultInvalid);
    }

    let validation = validate_did_transition(
        old,
        document,
        DomainVerificationEnv {
            resolve_txt: None,
            fetch_url: None,
        },
    );
    if !validation.ok {
        return Err(DidApiError::UpdateResultInvalid);
    }
    Ok(())
}

fn expected_bool_property(
    update: Option<DidBoolPropertyUpdate>,
    current: Option<bool>,
) -> Option<bool> {
    match update {
        None => current,
        Some(DidBoolPropertyUpdate::Set(value)) => Some(value),
        Some(DidBoolPropertyUpdate::Clear) => None,
    }
}

fn expected_string_property<'a>(
    update: Option<&'a DidStringPropertyUpdate>,
    current: Option<&'a str>,
) -> Option<&'a str> {
    match update {
        None => current,
        Some(DidStringPropertyUpdate::Set(value)) => Some(value.as_str()),
        Some(DidStringPropertyUpdate::Clear) => None,
    }
}

fn expected_owned_string_property(
    update: Option<&DidStringPropertyUpdate>,
    current: Option<&String>,
) -> Option<String> {
    match update {
        None => current.cloned(),
        Some(DidStringPropertyUpdate::Set(value)) => Some(value.clone()),
        Some(DidStringPropertyUpdate::Clear) => None,
    }
}

fn string_property_update_is_valid(update: Option<&DidStringPropertyUpdate>) -> bool {
    update.is_none_or(|update| match update {
        DidStringPropertyUpdate::Set(value) => text_is_valid(value),
        DidStringPropertyUpdate::Clear => true,
    })
}

fn text_values_are_valid(values: &[String]) -> bool {
    values.iter().all(|value| text_is_valid(value))
}

fn text_is_valid(value: &str) -> bool {
    !value.is_empty() && value.len() <= MAX_DID_UPDATE_TEXT_BYTES
}

/// Provider-backed `identity.dids.resolve`.
pub fn resolve_did_command<P: DidProvider + ?Sized>(
    provider: &P,
    request: DidResolveRequest,
) -> Result<DidResolutionResult, DidApiError> {
    crate::resolve::resolve_did_with_provider(provider, request)
}

/// Provider-backed `identity.dids.deactivate`.
pub fn deactivate_did_with_provider<P: DidProvider + ?Sized>(
    provider: &P,
    request: DidDeactivateRequest,
) -> Result<DIDDocument, DidApiError> {
    validate_deactivation_request(&request)?;
    let document = provider.deactivate_did(&request)?;
    validate_deactivated_document(&request, &document)?;
    Ok(document)
}

/// Deactivate through an injected provider and adopt the validated terminal
/// document into a non-cloneable zeroizing owner for canonical dispatch.
pub fn deactivate_did_with_provider_owned<P: DidProvider + ?Sized>(
    provider: &P,
    request: DidDeactivateRequest,
) -> Result<SensitiveDidDeactivatedDocument, DidApiError> {
    deactivate_did_with_provider(provider, request)
        .map(SensitiveDidDeactivatedDocument::from_document)
}

fn validate_deactivation_request(request: &DidDeactivateRequest) -> Result<(), DidApiError> {
    let document = &request.document;
    let validation = validate_did_consistency(
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
        return Err(DidApiError::DeactivationRequestInvalid);
    }
    Ok(())
}

fn validate_deactivated_document(
    request: &DidDeactivateRequest,
    document: &DIDDocument,
) -> Result<(), DidApiError> {
    let old = &request.document;
    let expected_sequence = old
        .sequence
        .checked_add(1)
        .ok_or(DidApiError::DeactivationResultInvalid)?;
    let expected_history_len = old
        .key_history
        .len()
        .checked_add(1)
        .ok_or(DidApiError::DeactivationResultInvalid)?;
    let history_is_valid = document.key_history.len() == expected_history_len
        && document
            .key_history
            .get(..old.key_history.len())
            .is_some_and(|history| history == old.key_history.as_slice())
        && document.key_history.last() == Some(&old.current_core);
    let preserved_projection_is_valid = document.id == old.id
        && document.controller == old.controller
        && document.context == old.context
        && document.also_known_as == old.also_known_as
        && document.hardware_bound == old.hardware_bound
        && document.biometric_protected == old.biometric_protected
        && document.user_verification_method == old.user_verification_method
        && document.device_model == old.device_model
        && document.domain_verification == old.domain_verification
        && document.eudi_level_of_assurance == old.eudi_level_of_assurance
        && document.eudi_schema_version == old.eudi_schema_version;
    let terminal_policy_is_valid = document.update_policy.as_ref().is_some_and(|policy| {
        policy.allowed_verification_methods.is_empty() && policy.threshold.is_none()
    });

    if document.sequence != expected_sequence
        || document.prev.as_ref() != Some(&old.current_core)
        || document.current_core == old.current_core
        || document.nonce.is_some()
        || !history_is_valid
        || !preserved_projection_is_valid
        || !document.verification_method.is_empty()
        || !document.authentication.is_empty()
        || !document.assertion_method.is_empty()
        || !document.capability_invocation.is_empty()
        || !document.key_agreement.is_empty()
        || !document.service.is_empty()
        || !terminal_policy_is_valid
        || document.attestations.is_empty()
        || document.data_integrity_proof.is_some()
    {
        return Err(DidApiError::DeactivationResultInvalid);
    }

    let validation = validate_did_transition(
        old,
        document,
        DomainVerificationEnv {
            resolve_txt: None,
            fetch_url: None,
        },
    );
    if !validation.ok {
        return Err(DidApiError::DeactivationResultInvalid);
    }
    Ok(())
}

/// Provider-backed `identity.dids.keys.rotate`.
pub fn rotate_did_keys_with_provider<P: DidProvider + ?Sized>(
    provider: &P,
    request: DidRotateSelectedKeysRequest,
) -> Result<DIDDocument, DidApiError> {
    validate_rotation_request(
        &request.document,
        &request.verification_method_ids,
        request.created.as_ref(),
        DidApiError::KeyRotationRequestInvalid,
    )?;
    let document = provider.rotate_did_keys(&request)?;
    validate_rotated_document(
        &request.document,
        &request.verification_method_ids,
        request.created.as_ref(),
        &document,
        DidApiError::KeyRotationResultInvalid,
    )?;
    Ok(document)
}

/// Rotate selected keys through an injected provider and adopt the validated
/// document into a non-cloneable zeroizing owner for canonical dispatch.
pub fn rotate_did_keys_with_provider_owned<P: DidProvider + ?Sized>(
    provider: &P,
    request: DidRotateSelectedKeysRequest,
) -> Result<SensitiveDidRotatedDocument, DidApiError> {
    rotate_did_keys_with_provider(provider, request).map(SensitiveDidRotatedDocument::from_document)
}

fn validate_rotation_request(
    document: &DIDDocument,
    verification_method_ids: &[String],
    created: Option<&String>,
    invalid: DidApiError,
) -> Result<(), DidApiError> {
    let validation = validate_did_consistency(
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
    if !validation.ok
        || !has_update_authority
        || verification_method_ids.is_empty()
        || verification_method_ids.len() > MAX_DID_KEY_ROTATION_TARGETS
    {
        return Err(invalid);
    }

    for (index, identifier) in verification_method_ids.iter().enumerate() {
        if identifier.is_empty()
            || identifier.len() > MAX_DID_KEY_ROTATION_IDENTIFIER_BYTES
            || verification_method_ids[..index].contains(identifier)
            || !document
                .verification_method
                .iter()
                .any(|method| method.id == *identifier)
        {
            return Err(invalid);
        }
    }

    if document.data_integrity_proof.is_some() && created.is_none() {
        return Err(invalid);
    }
    if created.is_some_and(|created| {
        created.is_empty()
            || created.len() > MAX_DID_KEY_ROTATION_TIMESTAMP_BYTES
            || OffsetDateTime::parse(created, &Rfc3339).is_err()
    }) {
        return Err(invalid);
    }
    Ok(())
}

fn validate_rotated_document(
    old: &DIDDocument,
    verification_method_ids: &[String],
    created: Option<&String>,
    document: &DIDDocument,
    invalid: DidApiError,
) -> Result<(), DidApiError> {
    let expected_sequence = old.sequence.checked_add(1).ok_or(invalid)?;
    let expected_history_len = old.key_history.len().checked_add(1).ok_or(invalid)?;
    let history_is_valid = document.key_history.len() == expected_history_len
        && document
            .key_history
            .get(..old.key_history.len())
            .is_some_and(|history| history == old.key_history.as_slice())
        && document.key_history.last() == Some(&old.current_core);
    let projection_is_preserved = document.id == old.id
        && document.controller == old.controller
        && document.context == old.context
        && document.also_known_as == old.also_known_as
        && document.authentication == old.authentication
        && document.assertion_method == old.assertion_method
        && document.capability_invocation == old.capability_invocation
        && document.key_agreement == old.key_agreement
        && document.service == old.service
        && document.update_policy == old.update_policy
        && document.hardware_bound == old.hardware_bound
        && document.biometric_protected == old.biometric_protected
        && document.user_verification_method == old.user_verification_method
        && document.device_model == old.device_model
        && document.domain_verification == old.domain_verification
        && document.eudi_level_of_assurance == old.eudi_level_of_assurance
        && document.eudi_schema_version == old.eudi_schema_version;

    if document.sequence != expected_sequence
        || document.prev.as_ref() != Some(&old.current_core)
        || document.current_core == old.current_core
        || document.nonce.is_some()
        || !history_is_valid
        || !projection_is_preserved
        || !verification_methods_match_rotation(old, verification_method_ids, document)
        || !proof_matches_rotation(old, created, document)
        || document.attestations.is_empty()
    {
        return Err(invalid);
    }

    let validation = validate_did_transition(
        old,
        document,
        DomainVerificationEnv {
            resolve_txt: None,
            fetch_url: None,
        },
    );
    if !validation.ok {
        return Err(invalid);
    }
    Ok(())
}

fn verification_methods_match_rotation(
    old: &DIDDocument,
    verification_method_ids: &[String],
    document: &DIDDocument,
) -> bool {
    old.verification_method.len() == document.verification_method.len()
        && old
            .verification_method
            .iter()
            .zip(&document.verification_method)
            .enumerate()
            .all(|(index, (old_method, new_method))| {
                let selected = verification_method_ids.contains(&old_method.id);
                old_method.id == new_method.id
                    && old_method.vm_type == new_method.vm_type
                    && old_method.controller == new_method.controller
                    && old_method.algorithm == new_method.algorithm
                    && if selected {
                        !old.verification_method.iter().any(|method| {
                            method.public_key_multibase == new_method.public_key_multibase
                        }) && !document.verification_method[..index].iter().any(|method| {
                            method.public_key_multibase == new_method.public_key_multibase
                        })
                    } else {
                        old_method.public_key_multibase == new_method.public_key_multibase
                    }
            })
}
