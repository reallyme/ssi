// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Production did:web method semantics and provider contracts.
//!
//! Identifier and document processing are pure. DNS, HTTPS, cancellation, and
//! authenticated publication are explicit injected boundaries so applications
//! can enforce their own platform policy without changing method semantics.

mod dereference;
mod did_url;
mod document;
mod error;
mod method;
mod provider;
mod resolution;

pub use dereference::{
    dereference_did_web_document, DidWebDereferenceKind, DidWebDereferenceResult,
};
pub use document::{parse_and_validate_did_web_document, DidWebDocument, DidWebDocumentLimits};
pub use error::{
    DidWebError, DidWebErrorReason, DidWebHostingError, DidWebHostingErrorReason,
    DidWebTransportError, DidWebTransportErrorReason,
};
pub use method::{
    canonicalize_did_web, did_web_document_url, generate_did_web, is_valid_did_web, parse_did_web,
    DidWebIdentifier, WebDidInput,
};
pub use provider::{
    create_did_web_document, deactivate_did_web_document, update_did_web_document,
    AuthenticatedDidWebHostingProvider, DidWebHostingOperation, DidWebHostingReceipt,
    DidWebPublicationRequest, DidWebPublicationResult,
};
pub use resolution::{
    resolve_did_web_document, DidWebCancellation, DidWebDestinationPolicy, DidWebHttpRequest,
    DidWebHttpResponse, DidWebMediaType, DidWebNetworkResolver, DidWebResolutionPolicy,
    DidWebResolutionResult, PublicInternetDestinationPolicy,
};
