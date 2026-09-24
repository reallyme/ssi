// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! DID identity-core engine for canonical state, document projection, validation, and updates.

/// Core attestation types.
pub mod attestation;
/// Canonical CBOR conversion utilities.
pub mod canonical;
/// Canonical DID state types used by supported identity-core methods.
pub mod core;
/// DID document creation engine.
pub mod create;
/// DID document projection helpers.
pub mod document;
/// Core engine error types.
pub mod error;
/// Canonical core CID helpers.
pub mod hashing;
/// Core signature domain-separation helpers.
pub mod identifier;
/// Key generation and multikey conversion helpers.
pub mod keys;
/// Built-in DID profile definitions.
pub mod profile;
/// Core attestation signing helpers.
pub mod signing;
/// DID document update engine.
pub mod update;
/// DID document validation engine.
pub mod validate;

pub use core::{CanonicalService, CoreVerificationMethod, DidCore, UpdatePolicy};

pub use canonical::Canonical;
pub use error::DidCoreError;
pub use hashing::{compute_core_cid, verify_core_cid};
pub use identifier::core_signature_input;

pub use attestation::CoreAttestation;
pub use signing::sign_core;

pub use document::{default_context, project_did_document, DocumentProjection};

pub use create::{
    create_engine, CreateOptions, CreateResult, DomainVerificationInput, DomainVerificationPreset,
    ServiceInput,
};

pub use profile::{build_profile, DidProfile};

pub use update::{update_engine, UpdateMetadata, UpdateOptions, UpdateRelationships};

pub use keys::{generate_keypair_for_algorithm, public_key_to_multikey_for_algorithm};

pub use validate::{validate_did_document, FullValidationResult};

pub use validate::DataIntegrityProofValidationResult;
