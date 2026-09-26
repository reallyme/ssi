// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

fn validate_key_relationship_assignment_request(
    request: &DidSetKeyRelationshipsDocumentRequest,
) -> Result<(), DidApiError> {
    let invalid = DidApiError::KeyRelationshipAssignmentRequestInvalid;
    let validation = validate_did_consistency(
        &request.document,
        DomainVerificationEnv {
            resolve_txt: None,
            fetch_url: None,
        },
    );
    let policy = request.document.update_policy.as_ref().ok_or(invalid)?;
    if !validation.ok
        || policy.allowed_verification_methods.is_empty()
        || (request.authentication.is_none()
            && request.assertion_method.is_none()
            && request.capability_invocation.is_none()
            && request.key_agreement.is_none())
        || (request.threshold.is_some() && request.capability_invocation.is_none())
    {
        return Err(invalid);
    }

    validate_relationship_replacement(
        &request.document,
        request.authentication.as_deref(),
        RelationshipAlgorithmPolicy::Signing,
        true,
    )?;
    validate_relationship_replacement(
        &request.document,
        request.assertion_method.as_deref(),
        RelationshipAlgorithmPolicy::Signing,
        true,
    )?;
    validate_relationship_replacement(
        &request.document,
        request.key_agreement.as_deref(),
        RelationshipAlgorithmPolicy::KeyAgreement,
        true,
    )?;
    validate_relationship_replacement(
        &request.document,
        request.capability_invocation.as_deref(),
        RelationshipAlgorithmPolicy::Invocation,
        false,
    )?;

    if let Some(invocation) = request.capability_invocation.as_ref() {
        let threshold = request.threshold.or(policy.threshold).unwrap_or(1);
        let threshold = usize::try_from(threshold).map_err(|_| invalid)?;
        if threshold == 0 || threshold > invocation.len() {
            return Err(invalid);
        }
    }

    if let Some(proof) = request.document.data_integrity_proof.as_ref() {
        let expected_assertion = request
            .assertion_method
            .as_deref()
            .unwrap_or(&request.document.assertion_method);
        if request.created.is_none()
            || !proof
                .verification_method
                .as_deref()
                .is_some_and(|proof_method| {
                    expected_assertion.iter().any(|reference| {
                        verification_method_references_match(
                            &request.document.id,
                            reference,
                            proof_method,
                        )
                    })
                })
        {
            return Err(invalid);
        }
    }
    if request.created.as_ref().is_some_and(|created| {
        created.is_empty()
            || created.len() > MAX_DID_KEY_ROTATION_TIMESTAMP_BYTES
            || OffsetDateTime::parse(created, &Rfc3339).is_err()
    }) {
        return Err(invalid);
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum RelationshipAlgorithmPolicy {
    Signing,
    Invocation,
    KeyAgreement,
}

fn validate_relationship_replacement(
    document: &DIDDocument,
    references: Option<&[String]>,
    policy: RelationshipAlgorithmPolicy,
    empty_allowed: bool,
) -> Result<(), DidApiError> {
    let invalid = DidApiError::KeyRelationshipAssignmentRequestInvalid;
    let Some(references) = references else {
        return Ok(());
    };
    if references.len() > MAX_DID_KEY_ROTATION_TARGETS || (!empty_allowed && references.is_empty())
    {
        return Err(invalid);
    }
    for (index, reference) in references.iter().enumerate() {
        if reference.is_empty()
            || reference.len() > MAX_DID_KEY_ROTATION_IDENTIFIER_BYTES
            || references[..index].contains(reference)
        {
            return Err(invalid);
        }
        let method = document
            .verification_method
            .iter()
            .find(|method| method.id == *reference)
            .ok_or(invalid)?;
        let algorithm = method
            .algorithm
            .as_deref()
            .ok_or(invalid)
            .and_then(|value| alg_str_to_alg(value).map_err(|_| invalid))?;
        let allowed = match policy {
            RelationshipAlgorithmPolicy::Signing => {
                matches!(
                    algorithm,
                    Algorithm::Ed25519 | Algorithm::MlDsa87 | Algorithm::P256
                )
            }
            RelationshipAlgorithmPolicy::Invocation => matches!(
                algorithm,
                Algorithm::Ed25519 | Algorithm::MlDsa87 | Algorithm::P256 | Algorithm::Secp256k1
            ),
            RelationshipAlgorithmPolicy::KeyAgreement => matches!(
                algorithm,
                Algorithm::X25519 | Algorithm::MlKem768 | Algorithm::MlKem1024
            ),
        };
        if !allowed {
            return Err(invalid);
        }
    }
    Ok(())
}

fn validate_key_relationship_assignment_result(
    request: &DidSetKeyRelationshipsDocumentRequest,
    document: &DIDDocument,
) -> Result<(), DidApiError> {
    let invalid = DidApiError::KeyRelationshipAssignmentResultInvalid;
    let old = &request.document;
    let expected_sequence = old.sequence.checked_add(1).ok_or(invalid)?;
    let expected_history_len = old.key_history.len().checked_add(1).ok_or(invalid)?;
    let history_is_valid = document.key_history.len() == expected_history_len
        && document
            .key_history
            .get(..old.key_history.len())
            .is_some_and(|history| history == old.key_history.as_slice())
        && document.key_history.last() == Some(&old.current_core);
    let expected_authentication = request
        .authentication
        .as_deref()
        .unwrap_or(&old.authentication);
    let expected_assertion = request
        .assertion_method
        .as_deref()
        .unwrap_or(&old.assertion_method);
    let expected_invocation = request
        .capability_invocation
        .as_deref()
        .unwrap_or(&old.capability_invocation);
    let expected_key_agreement = request
        .key_agreement
        .as_deref()
        .unwrap_or(&old.key_agreement);
    let old_policy = old.update_policy.as_ref().ok_or(invalid)?;
    let expected_policy_allowed = request
        .capability_invocation
        .as_deref()
        .unwrap_or(&old_policy.allowed_verification_methods);
    let expected_threshold = if request.capability_invocation.is_some() {
        request.threshold.or(old_policy.threshold)
    } else {
        old_policy.threshold
    };
    let projection_is_exact = document.id == old.id
        && document.controller == old.controller
        && document.context == old.context
        && document.also_known_as == old.also_known_as
        && document.verification_method == old.verification_method
        && document.authentication == expected_authentication
        && document.assertion_method == expected_assertion
        && document.capability_invocation == expected_invocation
        && document.key_agreement == expected_key_agreement
        && document.service == old.service
        && document.update_policy.as_ref().is_some_and(|policy| {
            policy.allowed_verification_methods == expected_policy_allowed
                && policy.threshold == expected_threshold
        })
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
        || !projection_is_exact
        || !proof_matches_rotation(old, request.created.as_ref(), document)
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
