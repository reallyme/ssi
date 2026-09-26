// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

fn proof_matches_rotation(
    old: &DIDDocument,
    created: Option<&String>,
    document: &DIDDocument,
) -> bool {
    match (
        old.data_integrity_proof.as_ref(),
        document.data_integrity_proof.as_ref(),
    ) {
        (None, None) => true,
        (Some(old_proof), Some(new_proof)) => {
            old_proof.proof_type == new_proof.proof_type
                && old_proof.cryptosuite == new_proof.cryptosuite
                && old_proof.proof_purpose == new_proof.proof_purpose
                && old_proof.verification_method == new_proof.verification_method
                && new_proof.created.as_ref() == created
                && old_proof.jws != new_proof.jws
        }
        (None, Some(_)) | (Some(_), None) => false,
    }
}

/// Provider-backed `identity.dids.keys.rotateRelationship`.
pub fn rotate_did_relationship_keys_with_provider<P: DidProvider + ?Sized>(
    provider: &P,
    request: DidRotateRelationshipKeysDocumentRequest,
) -> Result<DIDDocument, DidApiError> {
    let verification_method_ids = relationship_rotation_ids(&request)?;
    validate_rotation_request(
        &request.document,
        verification_method_ids,
        request.created.as_ref(),
        DidApiError::RelationshipKeyRotationRequestInvalid,
    )?;
    let document = provider.rotate_did_relationship_keys(&request)?;
    validate_rotated_document(
        &request.document,
        verification_method_ids,
        request.created.as_ref(),
        &document,
        DidApiError::RelationshipKeyRotationResultInvalid,
    )?;
    Ok(document)
}

/// Rotate relationship keys through an injected provider and adopt the
/// validated document into a non-cloneable zeroizing owner.
pub fn rotate_did_relationship_keys_with_provider_owned<P: DidProvider + ?Sized>(
    provider: &P,
    request: DidRotateRelationshipKeysDocumentRequest,
) -> Result<SensitiveDidRotatedDocument, DidApiError> {
    rotate_did_relationship_keys_with_provider(provider, request)
        .map(SensitiveDidRotatedDocument::from_document)
}

fn relationship_rotation_ids(
    request: &DidRotateRelationshipKeysDocumentRequest,
) -> Result<&[String], DidApiError> {
    let identifiers = match request.relationship {
        RekeyRelationship::Authentication => &request.document.authentication,
        RekeyRelationship::AssertionMethod => &request.document.assertion_method,
        RekeyRelationship::CapabilityInvocation => &request.document.capability_invocation,
        RekeyRelationship::KeyAgreement => &request.document.key_agreement,
        RekeyRelationship::Assertion
        | RekeyRelationship::CapabilityDelegation
        | RekeyRelationship::Controller => {
            return Err(DidApiError::RelationshipKeyRotationRequestInvalid);
        }
    };
    Ok(identifiers)
}

/// Provider-backed `identity.dids.keys.replaceCompromised`.
pub fn replace_compromised_did_keys_with_provider<P: DidProvider + ?Sized>(
    provider: &P,
    request: DidReplaceCompromisedKeysRequest,
) -> Result<DIDDocument, DidApiError> {
    validate_rotation_request(
        &request.document,
        &request.compromised_verification_method_ids,
        request.created.as_ref(),
        DidApiError::CompromisedKeyReplacementRequestInvalid,
    )?;
    validate_recovery_authority(&request)?;
    let document = provider.replace_compromised_did_keys(&request)?;
    validate_rotated_document(
        &request.document,
        &request.compromised_verification_method_ids,
        request.created.as_ref(),
        &document,
        DidApiError::CompromisedKeyReplacementResultInvalid,
    )?;
    validate_recovery_attestations(&request, &document)?;
    Ok(document)
}

/// Replace compromised keys through an injected provider and adopt the
/// validated recovered document into a non-cloneable zeroizing owner.
pub fn replace_compromised_did_keys_with_provider_owned<P: DidProvider + ?Sized>(
    provider: &P,
    request: DidReplaceCompromisedKeysRequest,
) -> Result<SensitiveDidRotatedDocument, DidApiError> {
    replace_compromised_did_keys_with_provider(provider, request)
        .map(SensitiveDidRotatedDocument::from_document)
}

fn validate_recovery_authority(
    request: &DidReplaceCompromisedKeysRequest,
) -> Result<(), DidApiError> {
    let invalid = DidApiError::CompromisedKeyReplacementRequestInvalid;
    let policy = request.document.update_policy.as_ref().ok_or(invalid)?;
    let threshold = usize::try_from(policy.threshold.unwrap_or(1)).map_err(|_| invalid)?;
    let remaining_authorities = policy
        .allowed_verification_methods
        .iter()
        .filter(|allowed| {
            !request
                .compromised_verification_method_ids
                .iter()
                .any(|compromised| {
                    verification_method_references_match(&request.document.id, allowed, compromised)
                })
        })
        .count();
    if threshold == 0 || remaining_authorities < threshold {
        return Err(invalid);
    }
    Ok(())
}

fn validate_recovery_attestations(
    request: &DidReplaceCompromisedKeysRequest,
    document: &DIDDocument,
) -> Result<(), DidApiError> {
    let invalid = DidApiError::CompromisedKeyReplacementResultInvalid;
    let policy = request.document.update_policy.as_ref().ok_or(invalid)?;
    let threshold = usize::try_from(policy.threshold.unwrap_or(1)).map_err(|_| invalid)?;
    for (index, attestation) in document.attestations.iter().enumerate() {
        let compromised_signer =
            request
                .compromised_verification_method_ids
                .iter()
                .any(|compromised| {
                    verification_method_references_match(
                        &request.document.id,
                        &attestation.vm,
                        compromised,
                    )
                });
        let authorized_signer = policy.allowed_verification_methods.iter().any(|allowed| {
            verification_method_references_match(&request.document.id, &attestation.vm, allowed)
        });
        let duplicate_signer = document.attestations[..index].iter().any(|prior| {
            verification_method_references_match(&request.document.id, &attestation.vm, &prior.vm)
        });
        if compromised_signer || !authorized_signer || duplicate_signer {
            return Err(invalid);
        }
    }
    if threshold == 0 || document.attestations.len() < threshold {
        return Err(invalid);
    }
    Ok(())
}

fn verification_method_references_match(did: &str, left: &str, right: &str) -> bool {
    if left == right {
        return true;
    }
    if let Some(left_fragment) = left.strip_prefix(did) {
        return left_fragment == right;
    }
    if let Some(right_fragment) = right.strip_prefix(did) {
        return left == right_fragment;
    }
    false
}

/// Provider-backed `identity.dids.keys.rotateAll`.
pub fn rotate_all_did_keys_with_provider<P: DidProvider + ?Sized>(
    provider: &P,
    request: DidRotateAllDocumentKeysRequest,
) -> Result<DIDDocument, DidApiError> {
    let verification_method_ids = Zeroizing::new(
        request
            .document
            .verification_method
            .iter()
            .map(|method| method.id.clone())
            .collect::<Vec<_>>(),
    );
    validate_rotation_request(
        &request.document,
        verification_method_ids.as_slice(),
        request.created.as_ref(),
        DidApiError::AllKeyRotationRequestInvalid,
    )?;
    let document = provider.rotate_all_did_keys(&request)?;
    validate_rotated_document(
        &request.document,
        verification_method_ids.as_slice(),
        request.created.as_ref(),
        &document,
        DidApiError::AllKeyRotationResultInvalid,
    )?;
    Ok(document)
}

/// Rotate every document key through an injected provider and adopt the
/// validated result into a non-cloneable zeroizing owner.
pub fn rotate_all_did_keys_with_provider_owned<P: DidProvider + ?Sized>(
    provider: &P,
    request: DidRotateAllDocumentKeysRequest,
) -> Result<SensitiveDidRotatedDocument, DidApiError> {
    rotate_all_did_keys_with_provider(provider, request)
        .map(SensitiveDidRotatedDocument::from_document)
}

/// Provider-backed `identity.dids.keys.setRelationships`.
pub fn set_did_key_relationships_with_provider<P: DidProvider + ?Sized>(
    provider: &P,
    request: DidSetKeyRelationshipsDocumentRequest,
) -> Result<DIDDocument, DidApiError> {
    validate_key_relationship_assignment_request(&request)?;
    let document = provider.set_did_key_relationships(&request)?;
    validate_key_relationship_assignment_result(&request, &document)?;
    Ok(document)
}

/// Assign relationships through an injected provider and adopt the validated
/// result into a non-cloneable zeroizing owner.
pub fn set_did_key_relationships_with_provider_owned<P: DidProvider + ?Sized>(
    provider: &P,
    request: DidSetKeyRelationshipsDocumentRequest,
) -> Result<SensitiveDidUpdatedDocument, DidApiError> {
    set_did_key_relationships_with_provider(provider, request)
        .map(SensitiveDidUpdatedDocument::from_document)
}

/// Designate MessagingService pre-keys through an explicitly injected provider.
pub fn designate_messaging_pre_keys_with_provider<P: DidProvider + ?Sized>(
    provider: &P,
    request: DidDesignateMessagingPreKeysRequest,
) -> Result<DIDDocument, DidApiError> {
    let expected_services = validate_messaging_pre_key_designation_request(&request)?;
    let document = provider.designate_messaging_pre_keys(&request)?;
    validate_messaging_pre_key_designation_result(&request, &expected_services, &document)?;
    Ok(document)
}

/// Designate pre-keys and adopt the validated document into a zeroizing owner.
pub fn designate_messaging_pre_keys_with_provider_owned<P: DidProvider + ?Sized>(
    provider: &P,
    request: DidDesignateMessagingPreKeysRequest,
) -> Result<SensitiveDidUpdatedDocument, DidApiError> {
    designate_messaging_pre_keys_with_provider(provider, request)
        .map(SensitiveDidUpdatedDocument::from_document)
}

/// Rotate the complete published hybrid pre-key set through an injected provider.
pub fn rotate_messaging_pre_keys_with_provider<P: DidProvider + ?Sized>(
    provider: &P,
    request: DidRotateMessagingPreKeysRequest,
) -> Result<DIDDocument, DidApiError> {
    let invalid = DidApiError::MessagingPreKeyRotationInvalid;
    if !text_is_valid(&request.service_id) {
        return Err(invalid);
    }
    let verification_method_ids = Zeroizing::new(
        crate::messaging::discover_controller_messaging_pre_keys(&request.document)
            .map_err(|_| invalid)?
            .into_iter()
            .find(|snapshot| snapshot.service_id == request.service_id)
            .map(|snapshot| snapshot.pre_keys.clone())
            .ok_or(invalid)?,
    );
    validate_rotation_request(
        &request.document,
        verification_method_ids.as_slice(),
        request.created.as_ref(),
        invalid,
    )?;
    let document = provider.rotate_messaging_pre_keys(&request)?;
    validate_rotated_document(
        &request.document,
        verification_method_ids.as_slice(),
        request.created.as_ref(),
        &document,
        invalid,
    )?;
    Ok(document)
}

/// Rotate pre-keys and adopt the validated document into a zeroizing owner.
pub fn rotate_messaging_pre_keys_with_provider_owned<P: DidProvider + ?Sized>(
    provider: &P,
    request: DidRotateMessagingPreKeysRequest,
) -> Result<SensitiveDidRotatedDocument, DidApiError> {
    rotate_messaging_pre_keys_with_provider(provider, request)
        .map(SensitiveDidRotatedDocument::from_document)
}

fn validate_messaging_pre_key_designation_request(
    request: &DidDesignateMessagingPreKeysRequest,
) -> Result<Zeroizing<Vec<Service>>, DidApiError> {
    let invalid = DidApiError::MessagingPreKeyDesignationInvalid;
    if !text_is_valid(&request.service_id)
        || !text_is_valid(&request.uri)
        || request.pre_keys.is_empty()
        || request.pre_keys.len() > MAX_DID_KEY_ROTATION_TARGETS
        || !text_values_are_valid(&request.pre_keys)
        || request
            .pre_keys
            .iter()
            .enumerate()
            .any(|(index, identifier)| request.pre_keys[..index].contains(identifier))
        || request.document.service.iter().any(|service| {
            service.id == request.service_id && service.service_type != "MessagingService"
        })
        || (request.document.data_integrity_proof.is_some() && request.created.is_none())
        || request.created.as_ref().is_some_and(|created| {
            created.is_empty()
                || created.len() > MAX_DID_KEY_ROTATION_TIMESTAMP_BYTES
                || OffsetDateTime::parse(created, &Rfc3339).is_err()
        })
    {
        return Err(invalid);
    }

    let expected_services = Zeroizing::new(
        services_with_designated_pre_keys(
            &request.document,
            request.service_id.clone(),
            request.uri.clone(),
            request.pre_keys.clone(),
        )
        .ok_or(invalid)?,
    );
    let update_request = DidUpdateRequest {
        document: request.document.clone(),
        services: Some(expected_services.as_slice().to_vec()),
        also_known_as: None,
        hardware_bound: None,
        biometric_protected: None,
        user_verification_method: None,
        device_model: None,
        domain_verification: None,
    };
    validate_update_request(&update_request).map_err(|_| invalid)?;
    Ok(expected_services)
}

fn validate_messaging_pre_key_designation_result(
    request: &DidDesignateMessagingPreKeysRequest,
    expected_services: &[Service],
    document: &DIDDocument,
) -> Result<(), DidApiError> {
    let invalid = DidApiError::MessagingPreKeyDesignationInvalid;
    let update_request = DidUpdateRequest {
        document: request.document.clone(),
        services: Some(expected_services.to_vec()),
        also_known_as: None,
        hardware_bound: None,
        biometric_protected: None,
        user_verification_method: None,
        device_model: None,
        domain_verification: None,
    };
    validate_updated_document(&update_request, document).map_err(|_| invalid)?;
    if !proof_matches_rotation(&request.document, request.created.as_ref(), document)
        || document.attestations.is_empty()
    {
        return Err(invalid);
    }
    Ok(())
}
