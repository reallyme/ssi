// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

/// Resolve through an injected provider and validate the returned did:me result.
pub fn resolve_did_with_provider<P: DidProvider + ?Sized>(
    provider: &P,
    request: DidResolveRequest,
) -> Result<DidResolutionResult, DidApiError> {
    let result = provider.resolve_did(request.clone())?;
    validate_resolution_result(&request, &result)?;
    Ok(result)
}

/// Resolve through an injected provider and adopt the validated result into a
/// non-cloneable zeroizing owner for canonical dispatch.
pub fn resolve_did_with_provider_owned<P: DidProvider + ?Sized>(
    provider: &P,
    request: DidResolveRequest,
) -> Result<SensitiveDidResolutionResult, DidApiError> {
    resolve_did_with_provider(provider, request).map(SensitiveDidResolutionResult::from_result)
}

/// Validate a provider-supplied resolution result against did:me taxonomy invariants.
pub fn validate_resolution_result(
    request: &DidResolveRequest,
    result: &DidResolutionResult,
) -> Result<(), DidApiError> {
    validate_resolution_request(request)?;
    let parsed = parse_did_url(&request.did)?;
    if parsed.is_did_url {
        return Err(DidApiError::InvalidDidUrl);
    }
    if !parsed.method_supported {
        return Err(DidApiError::UnsupportedDidMethod);
    }
    // This generic path validates did:me results only. did:web and did:ebsi are
    // resolved through their dedicated method-aware entry points.
    if parsed.method != GENERIC_RESOLUTION_METHOD {
        return Err(DidApiError::UnsupportedDidMethod);
    }

    match result.resolution_metadata.deactivation_status {
        DidDeactivationStatus::Absent => validate_absent_resolution(request, result),
        DidDeactivationStatus::Active => validate_present_resolution(request, result, false),
        DidDeactivationStatus::Deactivated => validate_present_resolution(request, result, true),
    }
}

fn validate_resolution_request(request: &DidResolveRequest) -> Result<(), DidApiError> {
    if request.did.is_empty() || request.did.len() > MAX_DID_RESOLUTION_IDENTIFIER_BYTES {
        return Err(DidApiError::InvalidDid);
    }
    if request.version_id.as_ref().is_some_and(|version_id| {
        version_id.is_empty() || version_id.len() > MAX_DID_RESOLUTION_IDENTIFIER_BYTES
    }) {
        return Err(DidApiError::InvalidDid);
    }
    if request.version_id.is_some() && request.version_time.is_some() {
        return Err(DidApiError::InvalidDid);
    }
    if request.version_time.as_deref().is_some_and(|version_time| {
        version_time.is_empty()
            || version_time.len() > MAX_DID_RESOLUTION_IDENTIFIER_BYTES
            || OffsetDateTime::parse(version_time, &Rfc3339).is_err()
    }) {
        return Err(DidApiError::InvalidDid);
    }
    Ok(())
}

fn validate_absent_resolution(
    request: &DidResolveRequest,
    result: &DidResolutionResult,
) -> Result<(), DidApiError> {
    let metadata = &result.resolution_metadata;
    if result.document.is_some()
        || result.document_metadata.is_some()
        || metadata.content_type.is_some()
        || metadata.assurance_achieved.is_some()
        || metadata.sequence.is_some()
        || metadata.error != Some(DidResolutionErrorCode::NotFound)
        || !optional_timestamp_is_valid(metadata.retrieved_at.as_deref())
        || !optional_metadata_is_valid(metadata.resolver.as_deref())
        || !result.history.is_empty()
        || !freshness_is_satisfied(request.freshness.as_ref(), metadata.retrieved_at.as_deref())
    {
        return Err(DidApiError::ResolutionResultInvalid);
    }

    Ok(())
}
