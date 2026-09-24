// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

/// Resolve did:ebsi through an injected registry and enforce historical selection.
pub fn resolve_did_ebsi_with_provider<P: DidProvider + ?Sized>(
    provider: &P,
    request: &DidResolveRequest,
) -> Result<DidEbsiResolution, DidApiError> {
    let method_request = DidEbsiResolveRequest {
        did: request.did.clone(),
        version_id: request.version_id.clone(),
        version_time: request.version_time.clone(),
        minimum_version_sequence: request.minimum_version_sequence,
    };
    let result = provider.resolve_did_ebsi(DidEbsiResolveRequest {
        did: request.did.clone(),
        version_id: request.version_id.clone(),
        version_time: request.version_time.clone(),
        minimum_version_sequence: request.minimum_version_sequence,
    })?;
    validate_did_ebsi_resolution(&method_request, &result).map_err(map_did_ebsi_error)?;
    let achieved = result.assurance_achieved.map(|value| match value {
        DidEbsiResolutionAssurance::AttestationVerified => {
            DidResolutionAssurance::AttestationVerified
        }
        DidEbsiResolutionAssurance::ChainVerified => DidResolutionAssurance::ChainVerified,
    });
    if request.assurance.is_some() && request.assurance != achieved {
        return Err(DidApiError::ResolutionResultInvalid);
    }
    if request.freshness.is_some() && result.retrieved_at.is_none() {
        return Err(DidApiError::ResolutionResultInvalid);
    }
    Ok(result)
}

struct DidEbsiRegistryProviderAdapter<'a, P: DidProvider + ?Sized> {
    provider: &'a P,
}

impl<P: DidProvider + ?Sized> AuthenticatedDidEbsiRegistryProvider
    for DidEbsiRegistryProviderAdapter<'_, P>
{
    fn is_authenticated_for(&self, operation: DidEbsiRegistryOperation) -> bool {
        self.provider.is_authenticated_for_did_ebsi(operation)
    }

    fn execute(
        &self,
        request: DidEbsiRegistryWriteRequest<'_>,
    ) -> Result<DidEbsiRegistryWriteResponse, DidEbsiRegistryProviderError> {
        self.provider.execute_did_ebsi_registry_write(request)
    }
}

/// Execute one authenticated EBSI registry mutation after pure preflight
/// validation and revalidate the correlated provider result.
#[allow(clippy::too_many_arguments)]
pub fn write_did_ebsi_with_provider<P: DidProvider + ?Sized>(
    provider: &P,
    operation: DidEbsiRegistryOperation,
    did: &str,
    current_document_json: Option<&[u8]>,
    proposed_document_json: &[u8],
    authorization_method: &str,
    target: Option<&str>,
    effective_at: Option<&str>,
) -> Result<DidEbsiRegistryWriteResult, DidApiError> {
    let adapter = DidEbsiRegistryProviderAdapter { provider };
    write_did_ebsi_registry_document(
        Some(&adapter),
        operation,
        did,
        current_document_json,
        proposed_document_json,
        authorization_method,
        target,
        effective_at,
        DidEbsiDocumentLimits::default(),
    )
    .map_err(map_did_ebsi_error)
}

fn map_did_ebsi_error(error: reallyme_did_method_ebsi::DidEbsiError) -> DidApiError {
    match error.reason {
        reallyme_did_method_ebsi::DidEbsiErrorReason::UnsupportedAlgorithm => {
            DidApiError::UnsupportedAlgorithm
        }
        reallyme_did_method_ebsi::DidEbsiErrorReason::ProviderUnavailable => {
            DidApiError::ProviderCapabilityUnsupported
        }
        reallyme_did_method_ebsi::DidEbsiErrorReason::UnauthorizedWrite
        | reallyme_did_method_ebsi::DidEbsiErrorReason::ProviderUnauthenticated => {
            DidApiError::PolicyViolation
        }
        reallyme_did_method_ebsi::DidEbsiErrorReason::DocumentIdentifierMismatch => {
            DidApiError::DidEbsiDocumentMismatch
        }
        reallyme_did_method_ebsi::DidEbsiErrorReason::InvalidTimeline
        | reallyme_did_method_ebsi::DidEbsiErrorReason::HistoricalVersionMismatch => {
            DidApiError::DidEbsiTimelineInvalid
        }
        reallyme_did_method_ebsi::DidEbsiErrorReason::RollbackDetected => {
            DidApiError::DidEbsiRollbackDetected
        }
        reallyme_did_method_ebsi::DidEbsiErrorReason::ProviderFailure => {
            DidApiError::DidEbsiRegistryFailure
        }
        reallyme_did_method_ebsi::DidEbsiErrorReason::InvalidPrefix
        | reallyme_did_method_ebsi::DidEbsiErrorReason::EmptyIdentifier
        | reallyme_did_method_ebsi::DidEbsiErrorReason::MissingMultibasePrefix
        | reallyme_did_method_ebsi::DidEbsiErrorReason::InvalidBase58
        | reallyme_did_method_ebsi::DidEbsiErrorReason::NonCanonicalEncoding
        | reallyme_did_method_ebsi::DidEbsiErrorReason::IdentifierTooLong
        | reallyme_did_method_ebsi::DidEbsiErrorReason::UnsupportedVersion
        | reallyme_did_method_ebsi::DidEbsiErrorReason::InvalidPayloadLength
        | reallyme_did_method_ebsi::DidEbsiErrorReason::InvalidDidUrl => {
            DidApiError::InvalidDid
        }
        reallyme_did_method_ebsi::DidEbsiErrorReason::ArithmeticOverflow
        | reallyme_did_method_ebsi::DidEbsiErrorReason::InvalidDocument
        | reallyme_did_method_ebsi::DidEbsiErrorReason::DocumentLimitExceeded
        | reallyme_did_method_ebsi::DidEbsiErrorReason::InvalidVersionSelector
        | reallyme_did_method_ebsi::DidEbsiErrorReason::ResolutionResultInvalid
        | reallyme_did_method_ebsi::DidEbsiErrorReason::InvalidKeyUsage
        | reallyme_did_method_ebsi::DidEbsiErrorReason::CapabilityInvocationMissing => {
            DidApiError::DidEbsiDocumentInvalid
        }
    }
}
