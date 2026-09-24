// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

fn validate_present_resolution(
    request: &DidResolveRequest,
    result: &DidResolutionResult,
    expected_deactivated: bool,
) -> Result<(), DidApiError> {
    let resolution_metadata = &result.resolution_metadata;
    if resolution_metadata.error.is_some()
        || !resolution_metadata
            .content_type
            .as_deref()
            .is_some_and(content_type_is_supported)
        || !optional_timestamp_is_valid(resolution_metadata.retrieved_at.as_deref())
        || !optional_metadata_is_valid(resolution_metadata.resolver.as_deref())
    {
        return Err(DidApiError::ResolutionResultInvalid);
    }
    let doc = result
        .document
        .as_ref()
        .ok_or(DidApiError::ResolutionResultInvalid)?;
    let metadata = result
        .document_metadata
        .as_ref()
        .ok_or(DidApiError::ResolutionResultInvalid)?;

    if !optional_timestamp_is_valid(metadata.created.as_deref())
        || !optional_timestamp_is_valid(metadata.updated.as_deref())
        || !optional_metadata_is_valid(metadata.version_id.as_deref())
        || !optional_metadata_is_valid(metadata.next_version_id.as_deref())
        || !optional_timestamp_is_valid(metadata.valid_from.as_deref())
        || !optional_timestamp_is_valid(metadata.valid_until.as_deref())
    {
        return Err(DidApiError::ResolutionResultInvalid);
    }

    if doc.id != request.did || metadata.deactivated != expected_deactivated {
        return Err(DidApiError::ResolutionResultInvalid);
    }

    if request.assurance.is_some()
        && request.assurance != resolution_metadata.assurance_achieved
    {
        return Err(DidApiError::ResolutionResultInvalid);
    }
    if request.freshness.is_some() && resolution_metadata.retrieved_at.is_none() {
        return Err(DidApiError::ResolutionResultInvalid);
    }

    if let Some(selected) = request.version_time.as_deref() {
        let selected = OffsetDateTime::parse(selected, &Rfc3339)
            .map_err(|_| DidApiError::ResolutionResultInvalid)?;
        let observed_version_time = metadata
            .updated
            .as_deref()
            .or(metadata.created.as_deref())
            .ok_or(DidApiError::ResolutionResultInvalid)
            .and_then(|value| {
                OffsetDateTime::parse(value, &Rfc3339)
                    .map_err(|_| DidApiError::ResolutionResultInvalid)
            })?;
        if observed_version_time > selected {
            return Err(DidApiError::ResolutionResultInvalid);
        }
    }

    if result
        .resolution_metadata
        .sequence
        .is_some_and(|sequence| sequence != doc.sequence)
    {
        return Err(DidApiError::ResolutionResultInvalid);
    }

    if metadata
        .version_id
        .as_ref()
        .is_some_and(|version_id| version_id != &doc.current_core)
    {
        return Err(DidApiError::ResolutionResultInvalid);
    }

    if document_is_terminal(doc) != expected_deactivated {
        return Err(DidApiError::ResolutionResultInvalid);
    }

    if let Some(version_id) = request.version_id.as_ref() {
        let version_in_chain =
            version_id == &doc.current_core || doc.key_history.iter().any(|v| v == version_id);
        if !version_in_chain {
            return Err(DidApiError::ResolutionResultInvalid);
        }
    }

    let validation = validate_did(
        doc,
        DomainVerificationEnv {
            resolve_txt: None,
            fetch_url: None,
        },
    );
    if !validation.ok {
        return Err(DidApiError::ResolutionResultInvalid);
    }

    Ok(())
}

fn content_type_is_supported(content_type: &str) -> bool {
    matches!(
        content_type,
        DID_JSON_CONTENT_TYPE | DID_LD_JSON_CONTENT_TYPE
    )
}

fn optional_metadata_is_valid(value: Option<&str>) -> bool {
    value.is_none_or(|value| !value.is_empty() && value.len() <= MAX_DID_RESOLUTION_METADATA_BYTES)
}

fn optional_timestamp_is_valid(value: Option<&str>) -> bool {
    value.is_none_or(|value| {
        !value.is_empty()
            && value.len() <= MAX_DID_RESOLUTION_METADATA_BYTES
            && OffsetDateTime::parse(value, &Rfc3339).is_ok()
    })
}

fn document_is_terminal(doc: &DIDDocument) -> bool {
    doc.verification_method.is_empty()
        && doc.authentication.is_empty()
        && doc.assertion_method.is_empty()
        && doc.capability_invocation.is_empty()
        && doc.key_agreement.is_empty()
        && doc.service.is_empty()
        && doc
            .update_policy
            .as_ref()
            .is_some_and(|policy| policy.allowed_verification_methods.is_empty())
}
