// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Ergonomic Rust API for ReallyMe DID generation, update, validation, and proto transport.

/// SDK command request types and provider-gated DID operations.
pub mod commands;
/// DID creation API.
pub mod create;
/// Local DID URL dereferencing.
pub mod dereference;
/// Domain verification helpers.
pub mod domain;
/// Typed API errors.
pub mod error;
/// Messaging pre-key discovery helpers.
pub mod messaging;
/// Offline DID parsing.
pub mod parse;
/// DID profile selectors.
pub mod profile;
/// Protobuf plus Brotli transport helpers.
pub mod proto;
/// Provider-injected DID resolution.
pub mod resolve;
/// Verification method rotation helpers.
pub mod rotate;
/// DID update API.
pub mod update;
/// DID validation API.
pub mod validate;

pub use error::DidApiError;

pub use reallyme_keys::KeySet;

pub use commands::{
    create_did_with_provider, create_did_with_provider_owned, deactivate_did_with_provider,
    deactivate_did_with_provider_owned, designate_messaging_pre_keys_with_provider,
    designate_messaging_pre_keys_with_provider_owned, replace_compromised_did_keys_with_provider,
    replace_compromised_did_keys_with_provider_owned, resolve_did_command,
    rotate_all_did_keys_with_provider, rotate_all_did_keys_with_provider_owned,
    rotate_did_keys_with_provider, rotate_did_keys_with_provider_owned,
    rotate_did_relationship_keys_with_provider, rotate_did_relationship_keys_with_provider_owned,
    rotate_messaging_pre_keys_with_provider, rotate_messaging_pre_keys_with_provider_owned,
    set_did_key_relationships_with_provider, set_did_key_relationships_with_provider_owned,
    update_did_with_provider, update_did_with_provider_owned, DidBoolPropertyUpdate,
    DidCreateRequest, DidDeactivateRequest, DidDesignateMessagingPreKeysRequest, DidMethod,
    DidReplaceCompromisedKeysRequest, DidRotateAllDocumentKeysRequest,
    DidRotateMessagingPreKeysRequest, DidRotateRelationshipKeysDocumentRequest,
    DidRotateSelectedKeysRequest, DidSetKeyRelationshipsDocumentRequest, DidStringPropertyUpdate,
    DidUpdateRequest, DidValidationRequest, SensitiveDidCreatedDocument,
    SensitiveDidDeactivatedDocument, SensitiveDidRotatedDocument, SensitiveDidUpdatedDocument,
};

pub use profile::{build_profile, DidProfile};

pub use create::{create_did, CreateConfig};

pub use dereference::{
    dereference_did_url, select_did_url_resource, DereferencedResource, DidDereferenceError,
    DidDereferenceRequest, DidDereferenceResult, DidDereferenceSelection,
};

pub use parse::{parse_did, parse_did_value, DidParseError, DidParseRequest, DidParseResult};

pub use resolve::{
    create_did_web_with_provider, deactivate_did_web_with_provider, resolve_did_ebsi_with_provider,
    resolve_did_web_with_provider, resolve_did_with_provider, resolve_did_with_provider_owned,
    update_did_web_with_provider, validate_resolution_result, write_did_ebsi_with_provider,
    DidDeactivationStatus, DidDocumentMetadata, DidProvider, DidProviderCapability,
    DidResolutionAssurance, DidResolutionErrorCode, DidResolutionFreshness, DidResolutionMetadata,
    DidResolutionResult, DidResolveRequest, DidWebProviderResolution, SensitiveDidResolutionResult,
};

pub use update::{
    deactivate_did, deactivate_did_validated, set_key_relationships, update_did,
    DeactivationResult, RelationshipAssignmentConfig, UpdateConfig,
};

pub use rotate::{
    replace_compromised_keys, rotate_all_keys, rotate_keys, rotate_relationship_keys,
    RekeyRelationship,
};

pub use messaging::{
    designate_messaging_pre_keys, discover_messaging_pre_keys, rotate_messaging_pre_keys,
    MessagingPreKeySnapshot,
};

pub use validate::{validate_did, validate_did_with_domain_evidence};

pub use domain::{
    validate_did_domain, validate_did_with_domain_verification, validate_domain_bindings,
    validate_single_domain_binding, SingleDomainValidationError,
};

pub use proto::{did_to_proto_brotli, proto_brotli_to_did};
