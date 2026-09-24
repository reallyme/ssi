// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! did:ebsi method identifier helpers.
//!
//! EBSI identifiers are versioned multibase Base58 BTC byte strings. Pure
//! identifier, document, timeline, and mutation validation live here; registry
//! transport, authentication, token acquisition, and transaction signing are
//! supplied through explicit provider adapters.

mod dereference;
mod document;
mod jwk;
mod method;
mod registry;
mod registry_transition;
mod resolution;

pub use dereference::{
    dereference_did_ebsi_document, DidEbsiDereferenceKind, DidEbsiDereferenceResult,
};
pub use document::{
    parse_and_validate_did_ebsi_document, parse_and_validate_did_ebsi_document_for_state,
    DidEbsiDocument, DidEbsiDocumentLimits, DidEbsiDocumentState,
};
pub use method::{
    generate_did_ebsi, is_valid_did_ebsi, parse_did_ebsi, DidEbsiError, DidEbsiErrorReason,
    EbsiDidIdentifier, EbsiDidVersion, EBSI_V1_PAYLOAD_LEN,
};
pub use registry::{
    create_did_ebsi_document, write_did_ebsi_registry_document,
    AuthenticatedDidEbsiRegistryProvider, DidEbsiRegistryOperation, DidEbsiRegistryProviderError,
    DidEbsiRegistryProviderErrorReason, DidEbsiRegistryWriteRequest, DidEbsiRegistryWriteResponse,
    DidEbsiRegistryWriteResult,
};
pub use resolution::{
    validate_did_ebsi_resolution, DidEbsiRegistryMetadata, DidEbsiResolution,
    DidEbsiResolutionAssurance, DidEbsiResolutionStatus, DidEbsiResolveRequest,
};
