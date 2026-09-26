// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0
/// Attestation validation for DID core signatures.
pub mod attestation;

/// Update authority decoded from signed canonical core state.
mod authority;

/// Canonical core CID and CBOR validation.
pub mod core;

/// Data Integrity proof schema validation.
pub mod data_integrity_proof;

/// Typed validation diagnostics shared by DID validators and adapters.
pub mod diagnostic;

/// Full DID Document validation orchestration.
pub mod did_document;

/// Domain binding consistency checks.
pub mod domain_binding;

/// Domain response matching checks.
pub mod domain_response;

/// Domain verification resolution hooks and entry validation.
pub mod domain_verification;

/// Resource limits applied to untrusted did:me documents.
pub mod limits;

/// JSON projection validation against canonical core content.
pub mod projection;

/// DID service validation.
pub mod service;

/// Top-level did:me document structure validation.
pub mod structure;

/// did:me update transition validation against the previous core state.
pub mod transition;

/// Update-policy validation.
pub mod update_policy;

/// Verification-method validation.
pub mod verification_method;

pub use structure::{validate_did_me_structure, StructureValidationResult};

pub use core::{validate_core_snapshot, CoreValidationResult, DidMeDocCoreView};

pub use attestation::{
    validate_attestation_policy, validate_attestations, AttestationPolicyValidationResult,
    AttestationValidationResult,
};

pub use service::{validate_services, ServiceValidationResult};

pub use verification_method::{validate_verification_methods, VerificationMethodValidationResult};

pub use data_integrity_proof::{
    validate_data_integrity_proof_schema, DataIntegrityProofValidationResult,
};

pub use update_policy::{validate_update_policy, UpdatePolicyValidationResult};

pub use projection::{validate_projection, ProjectionValidationResult};

pub use domain_verification::{
    validate_domain_entry, DidDocumentViewForDV, DomainVerificationEnv, DomainVerificationError,
};

pub use domain_binding::{validate_all_domain_bindings, validate_domain_binding};

pub use domain_response::{validate_domain_response, DomainResponse};

pub use did_document::{
    validate_did_document, validate_did_document_consistency, FullValidationResult,
};

pub use transition::validate_did_document_transition;

pub use diagnostic::{
    DidValidationCode, DidValidationIssue, DidValidationLocation, DidValidationSeverity,
};
