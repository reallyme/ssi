// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use identity_core_primitives::Algorithm;
use reallyme_did_types::DIDDocument;

use crate::error::DidApiError;
use crate::update::{update_did, update_did_with_authorization_exclusions, UpdateConfig};
use reallyme_keys::KeySet;

use reallyme_did_core::keys::{
    generate_keypair_for_algorithm, public_key_to_multikey_for_algorithm,
};

/// DID relationship used to select a group of keys for rotation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RekeyRelationship {
    /// Rotate keys listed in `authentication`.
    Authentication,

    /// Rotate keys listed in `assertionMethod`.
    AssertionMethod,

    /// Internal alias accepted by the update engine. Canonical transport does
    /// not expose this value.
    Assertion,

    /// Rotate keys listed in projected `capabilityInvocation`.
    CapabilityInvocation,

    /// Rotate keys listed in `keyAgreement`.
    KeyAgreement,

    /// DID Core relationship not defined by did:me v1.
    CapabilityDelegation,

    /// Generic controller relationship not defined as a did:me key relationship.
    Controller,
}

/// Rotate one or more verification methods (TS rotateKeys / Go Rotate)
pub fn rotate_keys(
    old_doc: &DIDDocument,
    ks: &KeySet,
    vm_ids: &[String],
    created: Option<String>,
) -> Result<(DIDDocument, KeySet), DidApiError> {
    if vm_ids.is_empty() {
        return Err(DidApiError::VerificationMethodSelectionRequired);
    }

    // 🔒 PRECONDITION: rotation invalidates DI proof
    if old_doc.data_integrity_proof.is_some() && created.is_none() {
        return Err(DidApiError::RotationRequiresCreated);
    }

    let new_ks = build_rotated_keyset(old_doc, ks, vm_ids)?;

    // Delegate to update engine
    update_did(
        old_doc,
        &new_ks,
        UpdateConfig {
            rotate_vms: Some(vm_ids.to_vec()),
            services: None,
            also_known_as: None,
            hardware_bound: None,
            biometric_protected: None,
            user_verification_method: None,
            device_model: None,
            allowed: None,
            threshold: None,
            deactivate: false,
            domain_verification: None,
            created,
            authentication: None,
            assertion: None,
            invocation: None,
            key_agreement: None,
        },
    )
}

fn build_rotated_keyset(
    old_doc: &DIDDocument,
    ks: &KeySet,
    vm_ids: &[String],
) -> Result<KeySet, DidApiError> {
    let mut new_ks = KeySet::new();
    ks.copy_into(&mut new_ks);

    for id in vm_ids {
        let vm = old_doc
            .verification_method
            .iter()
            .find(|v| &v.id == id)
            .ok_or(DidApiError::VerificationMethodNotFound)?;

        let alg = match vm.algorithm.as_deref() {
            Some("Ed25519") => Algorithm::Ed25519,
            Some("P-256") | Some("ES256") => Algorithm::P256,
            Some("secp256k1") => Algorithm::Secp256k1,
            Some("ML-DSA-87") => Algorithm::MlDsa87,
            Some("X25519") => Algorithm::X25519,
            Some("ML-KEM-768") => Algorithm::MlKem768,
            Some("ML-KEM-1024") => Algorithm::MlKem1024,
            Some(_) => return Err(DidApiError::UnsupportedAlgorithm),
            None => return Err(DidApiError::MissingVerificationMethodAlgorithm),
        };

        let (public, secret) =
            generate_keypair_for_algorithm(alg).map_err(|_| DidApiError::EngineFailure)?;

        let multikey = public_key_to_multikey_for_algorithm(alg, &public)
            .map_err(|_| DidApiError::EngineFailure)?;

        new_ks
            .put_key_zeroizing(id, secret, multikey)
            .map_err(|_| DidApiError::EngineFailure)?;
    }

    Ok(new_ks)
}

/// Rotate every verification method assigned to one DID relationship.
pub fn rotate_relationship_keys(
    old_doc: &DIDDocument,
    ks: &KeySet,
    relationship: RekeyRelationship,
    created: Option<String>,
) -> Result<(DIDDocument, KeySet), DidApiError> {
    let vm_ids = match relationship {
        RekeyRelationship::Authentication => old_doc.authentication.clone(),
        RekeyRelationship::Assertion | RekeyRelationship::AssertionMethod => {
            old_doc.assertion_method.clone()
        }
        RekeyRelationship::CapabilityInvocation => old_doc.capability_invocation.clone(),
        RekeyRelationship::KeyAgreement => old_doc.key_agreement.clone(),
        RekeyRelationship::CapabilityDelegation | RekeyRelationship::Controller => {
            return Err(DidApiError::UnsupportedDidRelationship);
        }
    };

    if vm_ids.is_empty() {
        return Err(DidApiError::VerificationMethodNotFound);
    }

    rotate_keys(old_doc, ks, &vm_ids, created)
}

/// Replace verification methods whose private material may be compromised.
///
/// This is intentionally separate from routine rotation because callers and
/// audit logs must preserve compromise semantics. did:me v1 represents
/// recovery by publishing an authorized core update that supersedes the named
/// verification methods and re-attests the resulting core. Destruction of
/// superseded private material is storage-provider responsibility; the
/// in-memory `KeySet` returned here contains only the replacement material for
/// the superseded verification method identifiers.
pub fn replace_compromised_keys(
    old_doc: &DIDDocument,
    ks: &KeySet,
    vm_ids: &[String],
    created: Option<String>,
) -> Result<(DIDDocument, KeySet), DidApiError> {
    if vm_ids.is_empty() {
        return Err(DidApiError::VerificationMethodSelectionRequired);
    }

    if old_doc.data_integrity_proof.is_some() && created.is_none() {
        return Err(DidApiError::RotationRequiresCreated);
    }

    let recovery_ks = build_rotated_keyset(old_doc, ks, vm_ids)?;

    update_did_with_authorization_exclusions(
        old_doc,
        &recovery_ks,
        UpdateConfig {
            rotate_vms: Some(vm_ids.to_vec()),
            services: None,
            also_known_as: None,
            hardware_bound: None,
            biometric_protected: None,
            user_verification_method: None,
            device_model: None,
            allowed: None,
            threshold: None,
            deactivate: false,
            domain_verification: None,
            created,
            authentication: None,
            assertion: None,
            invocation: None,
            key_agreement: None,
        },
        vm_ids,
    )
}

/// Rotate all verification methods in the DID Document.
pub fn rotate_all_keys(
    old_doc: &DIDDocument,
    ks: &KeySet,
    created: Option<String>,
) -> Result<(DIDDocument, KeySet), DidApiError> {
    let vm_ids: Vec<String> = old_doc
        .verification_method
        .iter()
        .map(|vm| vm.id.clone())
        .collect();

    if vm_ids.is_empty() {
        return Err(DidApiError::VerificationMethodNotFound);
    }

    rotate_keys(old_doc, ks, &vm_ids, created)
}
