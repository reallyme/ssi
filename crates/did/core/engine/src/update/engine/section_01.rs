// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use core::str::FromStr;
use identity_core_primitives::algorithm_map::alg_to_did_alg_str;
use identity_core_primitives::Algorithm;
use std::collections::HashMap;

use crate::canonical::Canonical;
use crate::canonical::{json_to_cbor_value, normalize_json_value};
use crate::core::{
    CanonicalService, CoreVerificationMethod, DidCore, UpdatePolicy as CoreUpdatePolicy,
};
use crate::document::{project_did_document, DocumentProjection};
use crate::error::DidCoreError;
use crate::hashing::compute_core_cid;
use crate::signing::sign_core_with_policy;
use crate::update::{
    error::UpdateError,
    invariants::validate_chain,
    merge::{merge_domain_verification, merge_services},
    rotation::apply_rotations,
};

use reallyme_did_types::{Attestation, DIDDocument, Service, VerificationMethod};
use std::collections::HashSet;

/// Internal update options assembled by the public facade.
pub struct UpdateOptions<'a> {
    /// Previous DID Document to update.
    pub old: &'a DIDDocument,

    /// Verification method id to rotation flag.
    pub rotate: HashMap<String, bool>,

    /// Replacement `updatePolicy.allowedVerificationMethods` value.
    pub allowed: Vec<String>,

    /// Replacement `updatePolicy.threshold` value.
    pub threshold: Option<u64>,

    /// Whether this update publishes the terminal deactivation core.
    pub deactivate: bool,

    /// Service override; `None` inherits, `Some([])` clears, and `Some(values)` replaces.
    pub services: Option<Vec<Service>>,

    /// Domain-verification override; `None` inherits and `Some(values)` replaces.
    pub domain_verification: Option<Vec<reallyme_did_types::DomainVerification>>,

    /// Relationship overrides applied to the next core snapshot.
    pub relationships: UpdateRelationships,

    /// Metadata override set.
    pub metadata: UpdateMetadata,

    /// Optional proof creation timestamp for regenerated Data Integrity proofs.
    pub created: Option<String>,
}

/// Relationship overrides applied during DID update.
pub struct UpdateRelationships {
    /// Replacement authentication relationship references.
    pub authentication: Option<Vec<String>>,

    /// Replacement assertionMethod relationship references.
    pub assertion: Option<Vec<String>>,

    /// Replacement keyAgreement relationship references.
    pub key_agreement: Option<Vec<String>>,
}

impl UpdateRelationships {
    /// Preserve all relationship arrays from the previous DID Document.
    pub fn inherit() -> Self {
        Self {
            authentication: None,
            assertion: None,
            key_agreement: None,
        }
    }
}

/// Metadata overrides applied during DID update.
pub struct UpdateMetadata {
    /// Replacement `alsoKnownAs` values.
    pub also_known_as: Option<Vec<String>>,

    /// Replacement hardware-bound metadata.
    pub hardware_bound: Option<bool>,

    /// Replacement biometric-protection metadata.
    pub biometric_protected: Option<bool>,

    /// Replacement user-verification metadata.
    pub user_verification_method: Option<String>,

    /// Replacement device-model metadata.
    pub device_model: Option<String>,
}

/// Convert JSON services → canonical services bytes
fn canonicalize_services(services: &[Service]) -> Result<Vec<CanonicalService>, UpdateError> {
    let mut out = Vec::new();

    for s in services {
        let normalized = normalize_json_value(&s.service_endpoint);
        let service_endpoint =
            json_to_cbor_value(&normalized).map_err(|_| UpdateError::InvalidState)?;

        out.push(CanonicalService {
            id: s.id.clone(),
            service_type: s.service_type.clone(),
            service_endpoint,
        });
    }

    Ok(out)
}

fn canonicalize_projected_verification_methods(
    input: &[VerificationMethod],
    core_keys: &[CoreVerificationMethod],
) -> Result<Vec<VerificationMethod>, UpdateError> {
    let mut out = Vec::with_capacity(input.len());

    for vm in input {
        let core_vm = core_keys
            .iter()
            .find(|core_vm| core_vm.id == vm.id)
            .ok_or(UpdateError::InvalidState)?;

        let mut projected = vm.clone();
        projected.vm_type = "Multikey".into();
        projected.algorithm = Some(alg_to_did_alg_str(core_vm.algorithm).to_owned());
        out.push(projected);
    }

    out.sort_by(|a, b| a.id.as_bytes().cmp(b.id.as_bytes()));
    Ok(out)
}

fn algorithm_for_key<'a>(
    keys: &'a [CoreVerificationMethod],
    id: &str,
) -> Option<&'a CoreVerificationMethod> {
    keys.iter().find(|key| key.id == id)
}

fn validate_relationship_references(
    authentication: &[String],
    assertion: &[String],
    key_agreement: &[String],
    allowed: &[String],
    threshold: Option<u64>,
    controller_keys: &[CoreVerificationMethod],
) -> Result<(), UpdateError> {
    if !refs_are_distinct(authentication)
        || !refs_are_distinct(assertion)
        || !refs_are_distinct(key_agreement)
        || !refs_are_distinct(allowed)
    {
        return Err(UpdateError::InvalidState);
    }

    for id in authentication {
        match algorithm_for_key(controller_keys, id).map(|key| key.algorithm) {
            Some(Algorithm::Ed25519 | Algorithm::MlDsa87 | Algorithm::P256) => {}
            _ => return Err(UpdateError::InvalidState),
        }
    }

    for id in assertion {
        match algorithm_for_key(controller_keys, id).map(|key| key.algorithm) {
            Some(Algorithm::Ed25519 | Algorithm::MlDsa87 | Algorithm::P256) => {}
            _ => return Err(UpdateError::InvalidState),
        }
    }

    for id in key_agreement {
        match algorithm_for_key(controller_keys, id).map(|key| key.algorithm) {
            Some(Algorithm::X25519 | Algorithm::MlKem768 | Algorithm::MlKem1024) => {}
            _ => return Err(UpdateError::InvalidState),
        }
    }

    for id in allowed {
        match algorithm_for_key(controller_keys, id).map(|key| key.algorithm) {
            Some(
                Algorithm::Ed25519 | Algorithm::MlDsa87 | Algorithm::P256 | Algorithm::Secp256k1,
            ) => {}
            _ => return Err(UpdateError::InvalidState),
        }
    }

    if let Some(threshold) = threshold {
        let threshold_usize = usize::try_from(threshold).map_err(|_| UpdateError::InvalidState)?;
        if threshold_usize == 0 || threshold_usize > allowed.len() {
            return Err(UpdateError::InvalidState);
        }
    }

    Ok(())
}

fn refs_are_distinct(refs: &[String]) -> bool {
    let mut seen = HashSet::new();
    refs.iter().all(|id| seen.insert(id.as_str()))
}
