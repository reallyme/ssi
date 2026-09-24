// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

/// Resolve did:web through an injected provider and enforce result invariants.
pub fn resolve_did_web_with_provider<P: DidProvider + ?Sized>(
    provider: &P,
    did: &str,
) -> Result<DidWebProviderResolution, DidApiError> {
    let identifier = parse_did_web(did).map_err(|_| DidApiError::InvalidDid)?;
    let result = provider.resolve_did_web(identifier.as_str())?;
    if result
        .document
        .as_ref()
        .is_some_and(|document| document.id() != Some(identifier.as_str()))
    {
        return Err(DidApiError::DidWebDocumentMismatch);
    }
    let valid = match result.deactivation_status {
        DidDeactivationStatus::Active => result.document.is_some() && result.media_type.is_some(),
        DidDeactivationStatus::Absent => result.document.is_none() && result.media_type.is_none(),
        DidDeactivationStatus::Deactivated => false,
    };
    if !valid {
        return Err(DidApiError::ResolutionResultInvalid);
    }
    Ok(result)
}

/// Publish did:web through an injected provider and verify the returned document binding.
pub fn create_did_web_with_provider<P: DidProvider + ?Sized>(
    provider: &P,
    did: &str,
    document: &DidWebDocument,
) -> Result<DidWebDocument, DidApiError> {
    let identifier = parse_did_web(did).map_err(|_| DidApiError::InvalidDid)?;
    if document.id() != Some(identifier.as_str()) {
        return Err(DidApiError::DidWebDocumentMismatch);
    }
    let created = provider.create_did_web(identifier.as_str(), document)?;
    if created.id() != Some(identifier.as_str()) {
        return Err(DidApiError::DidWebDocumentMismatch);
    }
    Ok(created)
}

/// Replace did:web through an injected provider and verify the returned document binding.
pub fn update_did_web_with_provider<P: DidProvider + ?Sized>(
    provider: &P,
    did: &str,
    document: &DidWebDocument,
) -> Result<DidWebDocument, DidApiError> {
    let identifier = parse_did_web(did).map_err(|_| DidApiError::InvalidDid)?;
    if document.id() != Some(identifier.as_str()) {
        return Err(DidApiError::DidWebDocumentMismatch);
    }
    let updated = provider.update_did_web(identifier.as_str(), document)?;
    if updated.id() != Some(identifier.as_str()) {
        return Err(DidApiError::DidWebDocumentMismatch);
    }
    Ok(updated)
}

/// Deactivate did:web through an injected provider after canonical identifier validation.
pub fn deactivate_did_web_with_provider<P: DidProvider + ?Sized>(
    provider: &P,
    did: &str,
) -> Result<(), DidApiError> {
    let identifier = parse_did_web(did).map_err(|_| DidApiError::InvalidDid)?;
    provider.deactivate_did_web(identifier.as_str())
}
