// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Local DID URL dereferencing for DID document and fragment resources.

use reallyme_did_types::{DIDDocument, Service, VerificationMethod};

use crate::error::DidApiError;
use crate::parse::{parse_did_value, DidParseError};

const DID_DOCUMENT_CONTENT_TYPE: &str = "application/did+json";
const DID_RESOURCE_CONTENT_TYPE: &str = "application/did+json;resource=fragment";

/// Typed, non-PII failures produced by local DID URL resource selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DidDereferenceError {
    /// The input does not have a valid DID URL structure.
    #[error("invalid DID URL")]
    InvalidDidUrl,

    /// The input fails method-specific DID validation.
    #[error("invalid DID")]
    InvalidDid,

    /// Local dereferencing cannot resolve a DID URL path or query.
    #[error("unsupported DID URL")]
    UnsupportedDidUrl,

    /// The fragment does not identify a resource in the supplied document.
    #[error("DID URL fragment not found")]
    FragmentNotFound,
}

impl From<DidDereferenceError> for DidApiError {
    fn from(error: DidDereferenceError) -> Self {
        match error {
            DidDereferenceError::InvalidDidUrl => Self::InvalidDidUrl,
            DidDereferenceError::InvalidDid => Self::InvalidDid,
            DidDereferenceError::UnsupportedDidUrl => Self::UnsupportedDidUrl,
            DidDereferenceError::FragmentNotFound => Self::DidUrlFragmentNotFound,
        }
    }
}

/// Location selected from a caller-owned DID document representation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DidDereferenceSelection {
    /// Select the complete DID document.
    Document,
    /// Select a verification method at the returned document index.
    VerificationMethod(usize),
    /// Select a service at the returned document index.
    Service(usize),
}

/// Request for local DID URL dereferencing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DidDereferenceRequest {
    /// DID or DID URL to dereference.
    pub did_url: String,
}

/// Resource selected by DID URL dereferencing.
#[derive(Debug, Clone)]
pub enum DereferencedResource {
    /// Whole DID document.
    Document(Box<DIDDocument>),
    /// Verification method selected by fragment.
    VerificationMethod(VerificationMethod),
    /// DID service selected by fragment.
    Service(Service),
}

/// Result of local DID URL dereferencing.
#[derive(Debug, Clone)]
pub struct DidDereferenceResult {
    /// Media type for the dereferenced resource.
    pub content_type: String,

    /// Dereferenced DID document resource.
    pub resource: DereferencedResource,
}

/// Dereference a DID URL against a caller-supplied document without network access.
pub fn dereference_did_url(
    doc: &DIDDocument,
    request: DidDereferenceRequest,
) -> Result<DidDereferenceResult, DidApiError> {
    let selection = select_did_url_resource(
        &doc.id,
        &doc.verification_method,
        &doc.service,
        |method| method.id.as_str(),
        |service| service.id.as_str(),
        &request.did_url,
    )
    .map_err(DidApiError::from)?;

    match selection {
        DidDereferenceSelection::Document => Ok(DidDereferenceResult {
            content_type: DID_DOCUMENT_CONTENT_TYPE.to_owned(),
            resource: DereferencedResource::Document(Box::new(doc.clone())),
        }),
        DidDereferenceSelection::VerificationMethod(index) => {
            let method = doc
                .verification_method
                .get(index)
                .ok_or(DidApiError::DidUrlFragmentNotFound)?;
            Ok(DidDereferenceResult {
                content_type: DID_RESOURCE_CONTENT_TYPE.to_owned(),
                resource: DereferencedResource::VerificationMethod(method.clone()),
            })
        }
        DidDereferenceSelection::Service(index) => {
            let service = doc
                .service
                .get(index)
                .ok_or(DidApiError::DidUrlFragmentNotFound)?;
            Ok(DidDereferenceResult {
                content_type: DID_RESOURCE_CONTENT_TYPE.to_owned(),
                resource: DereferencedResource::Service(service.clone()),
            })
        }
    }
}

/// Select a local DID URL resource without coupling selection policy to a
/// concrete document model.
///
/// The identifier accessors borrow directly from each representation. This
/// keeps protobuf dispatch from materializing a second, secret-bearing domain
/// document solely to perform a local lookup.
pub fn select_did_url_resource<V, S, FV, FS>(
    document_id: &str,
    verification_methods: &[V],
    services: &[S],
    verification_method_id: FV,
    service_id: FS,
    did_url: &str,
) -> Result<DidDereferenceSelection, DidDereferenceError>
where
    FV: for<'a> Fn(&'a V) -> &'a str,
    FS: for<'a> Fn(&'a S) -> &'a str,
{
    let parsed = parse_did_value(did_url).map_err(|error| match error {
        DidParseError::InvalidDidUrl => DidDereferenceError::InvalidDidUrl,
        DidParseError::InvalidDid => DidDereferenceError::InvalidDid,
    })?;

    if parsed.did != document_id {
        return Err(DidDereferenceError::InvalidDidUrl);
    }

    if parsed.path.is_some() || parsed.query.is_some() {
        return Err(DidDereferenceError::UnsupportedDidUrl);
    }

    let Some(fragment) = parsed.fragment.as_deref() else {
        return Ok(DidDereferenceSelection::Document);
    };

    if let Some(index) = verification_methods.iter().position(|method| {
        resource_identifier_matches(verification_method_id(method), did_url, fragment)
    }) {
        return Ok(DidDereferenceSelection::VerificationMethod(index));
    }

    if let Some(index) = services
        .iter()
        .position(|service| resource_identifier_matches(service_id(service), did_url, fragment))
    {
        return Ok(DidDereferenceSelection::Service(index));
    }

    Err(DidDereferenceError::FragmentNotFound)
}

fn resource_identifier_matches(identifier: &str, did_url: &str, fragment: &str) -> bool {
    identifier == did_url || identifier.strip_prefix('#') == Some(fragment)
}
