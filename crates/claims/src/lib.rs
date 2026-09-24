// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Protocol-neutral credential claim values, registries, paths, and disclosure validation.
//!
//! This crate is an identity core primitive. Protobuf/Buffa adapters and
//! envelope crates should map into these types instead of defining parallel
//! claim semantics. JSON is supported only as an explicit boundary
//! normalization input, not as a second internal schema.

mod commands;
mod commitment;
mod entries;
mod error;
mod json;
mod model;
mod paths;
/// Built-in credential claim registries.
pub mod profiles;
#[cfg(feature = "proto")]
mod proto;
mod registry;
mod validate;
mod values;

pub use commands::{
    classify_claim_sensitivity, compare_claims_json, define_claim, derive_claims_from_entries,
    get_claim_definition, list_claim_definitions, localize_claims, map_claims_json,
    normalize_claims_json, normalize_claims_json_slice, redact_claims_json, transform_claims_json,
    validate_claim_disclosure, validate_claims_json_slice, validate_claims_registry, ClaimMapping,
    ClaimSensitivity, ClaimSensitivityClassification, ClaimsCommandIssue, ClaimsCommandOutcome,
    ClaimsLocalizeResult, ClaimsMapResult, ClaimsNormalizeResult, ClaimsRedactResult,
    ClaimsSensitivityResult, ClaimsValidationResult, LocalizedClaimDisplay,
};
pub use commitment::{
    build_claims_commitment, default_commitment_domain_tags, default_commitment_limits,
    public_key_bytes, validate_claim_opening, validate_claims_commitment, validate_public_key_ref,
    validate_public_key_representation, validate_subject_private_bundle, verify_claim_opening,
    verify_subject_private_bundle, BuiltClaimsCommitment, ClaimCommitmentBuildInput, ClaimOpening,
    ClaimSaltSource, ClaimsCommitment, CommitmentLimits, CredentialAlgorithm, DomainTags,
    KeyAssurance, KeyReference, MerkleTreeInfo, PublicKeyRef, PublicKeyRepresentation,
    RawPublicKeySerialization, Signature, SubjectPrivateBundle, CLAIM_COMMITMENT_HASH_ALG_SHA256,
    CLAIM_COMMITMENT_HASH_BYTES, CLAIM_COMMITMENT_VALUE_ENCODING, DEFAULT_COMMITMENT_MAX_VALUE_LEN,
    DEFAULT_COMMITMENT_SALT_LEN, MAX_CLAIM_OPENINGS_PER_BUNDLE, MAX_CLAIM_OPENING_MERKLE_DEPTH,
    MAX_COMMITMENT_DOMAIN_TAG_BYTES, MAX_COMMITMENT_LABEL_BYTES, MAX_KEY_ASSURANCE_CERTIFICATES,
    MAX_PUBLIC_KEY_MATERIAL_BYTES,
};
pub use entries::{claim_value_from_path_entries, ClaimPathEntry};
pub use error::{ClaimsError, ClaimsInvalidReason};
pub use json::{claim_value_from_json, claim_value_from_json_slice};
pub use model::{
    ClaimDefinition, ClaimDisclosurePolicy, ClaimType, ClaimsRegistry, DisclosureMode,
    ENCODING_JCS_UTF8,
};
pub use paths::{
    claim_id_from_path, claim_path, escape_field_segment, is_valid_claim_id, parse_claim_path,
    ClaimPath, ClaimPathSegment, MAX_CLAIM_PATH_BYTES, MAX_CLAIM_PATH_DEPTH,
    MAX_CLAIM_PATH_SEGMENT_BYTES,
};
#[cfg(feature = "proto")]
pub use proto::{
    claim_definition_from_proto, claim_definition_to_proto, claims_commitment_from_proto,
    claims_commitment_to_proto, disclosure_policy_from_proto, disclosure_policy_to_proto,
    public_key_material_from_proto, public_key_material_to_proto, public_key_ref_from_proto,
    public_key_ref_to_proto, registry_from_proto, registry_to_proto,
    subject_private_bundle_from_proto, subject_private_bundle_to_proto,
};
pub use validate::{
    validate_claim_definition, validate_claim_payload, validate_claim_value, validate_disclosure,
    validate_registry, MAX_CLAIMS_PER_REGISTRY, MAX_CLAIM_ID_BYTES, MAX_DISCLOSURE_PREDICATES,
};
pub use values::{
    resolve_claim_path, ClaimDate, ClaimDateTime, ClaimDecimal, ClaimValue, MAX_CLAIM_ARRAY_ITEMS,
    MAX_CLAIM_BYTES_VALUE_BYTES, MAX_CLAIM_OBJECT_PROPERTIES, MAX_CLAIM_STRING_BYTES,
    MAX_CLAIM_VALUE_DEPTH,
};
