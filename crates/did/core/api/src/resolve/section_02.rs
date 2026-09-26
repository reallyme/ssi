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

    if request.assurance.is_some() && request.assurance != resolution_metadata.assurance_achieved {
        return Err(DidApiError::ResolutionResultInvalid);
    }
    if !freshness_is_satisfied(
        request.freshness.as_ref(),
        resolution_metadata.retrieved_at.as_deref(),
    ) {
        return Err(DidApiError::ResolutionResultInvalid);
    }

    validate_version_window(request, metadata)?;

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

    // A non-genesis document is authenticated only through its verified
    // history; a genesis document must not carry one.
    let expected_history_len = usize::try_from(doc.sequence.saturating_sub(1))
        .map_err(|_| DidApiError::ResolutionResultInvalid)?;
    if result.history.len() != expected_history_len {
        return Err(DidApiError::ResolutionResultInvalid);
    }
    let validation = validate_did_with_history(
        &result.history,
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

/// Enforce the caller's staleness bound against a caller-trusted clock.
fn freshness_is_satisfied(
    freshness: Option<&DidResolutionFreshness>,
    retrieved_at: Option<&str>,
) -> bool {
    let Some(freshness) = freshness else {
        return true;
    };
    let Some(retrieved_at) = retrieved_at else {
        return false;
    };
    let Ok(retrieved_at) = OffsetDateTime::parse(retrieved_at, &Rfc3339) else {
        return false;
    };
    let retrieved_at = i128::from(retrieved_at.unix_timestamp());
    let now = i128::from(freshness.trusted_now_unix_seconds);

    let Some(latest_accepted) = now.checked_add(i128::from(MAX_DID_RESOLUTION_CLOCK_SKEW_SECONDS))
    else {
        return false;
    };
    if retrieved_at > latest_accepted {
        return false;
    }
    match now.checked_sub(retrieved_at) {
        Some(age) => age <= i128::from(freshness.maximum_staleness_seconds),
        None => false,
    }
}

/// Require the returned version to have been valid at the selected instant.
fn validate_version_window(
    request: &DidResolveRequest,
    metadata: &DidDocumentMetadata,
) -> Result<(), DidApiError> {
    let parse = |value: &str| {
        OffsetDateTime::parse(value, &Rfc3339).map_err(|_| DidApiError::ResolutionResultInvalid)
    };
    let valid_from = metadata.valid_from.as_deref().map(parse).transpose()?;
    let valid_until = metadata.valid_until.as_deref().map(parse).transpose()?;
    if let (Some(start), Some(end)) = (valid_from, valid_until) {
        if end <= start {
            return Err(DidApiError::ResolutionResultInvalid);
        }
    }

    let Some(selected) = request.version_time.as_deref() else {
        // Without a historical selector the current version is required.
        if request.version_id.is_none() && metadata.valid_until.is_some() {
            return Err(DidApiError::ResolutionResultInvalid);
        }
        return Ok(());
    };
    let selected = parse(selected)?;

    let observed_version_time = metadata
        .updated
        .as_deref()
        .or(metadata.created.as_deref())
        .ok_or(DidApiError::ResolutionResultInvalid)
        .and_then(parse)?;
    if observed_version_time > selected {
        return Err(DidApiError::ResolutionResultInvalid);
    }

    // A superseded version must carry its exclusive end bound.
    if metadata.next_version_id.is_some() && valid_until.is_none() {
        return Err(DidApiError::ResolutionResultInvalid);
    }
    if valid_from.is_some_and(|start| selected < start)
        || valid_until.is_some_and(|end| selected >= end)
    {
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
