// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::canonical::{cbor_to_json_value, Canonical};
use crate::core::DidCore;
use crate::error::DidCoreError;

use reallyme_codec::base64url::bytes_to_base64url;
use reallyme_did_types::{
    Attestation, Controller, DIDDocument, DataIntegrityProof, DomainVerification, Service,
    UpdatePolicy, VerificationMethod,
};

/// Fixed DID Document `@context` tuple for the did:me profile.
pub fn default_context() -> Vec<String> {
    vec![
        "https://www.w3.org/ns/did/v1".into(),
        "https://w3id.org/security/multikey/v1".into(),
        "https://did-me.org/ns/did-me/v1".into(),
    ]
}

/// Inputs required to project a DID core snapshot into a JSON DIDDocument.
///
/// This mirrors the TypeScript `document: DIDDocument = { ... }` construction.
pub struct DocumentProjection<'a> {
    /// Canonical core snapshot to project.
    pub core: &'a DidCore,

    /// CID of the canonical core snapshot.
    pub core_cid: &'a str,

    /// Additional subject identifiers for DID consumers.
    pub also_known_as: Vec<String>,

    /// Whether the identity is bound to hardware-protected key material.
    pub hardware_bound: Option<bool>,

    /// Whether the identity includes a biometric-protection claim.
    pub biometric_protected: Option<bool>,

    /// User-verification method label exposed by the wallet or device.
    pub user_verification_method: Option<String>,

    /// Device model label exposed by the wallet or device.
    pub device_model: Option<String>,

    /// EUDI wallet or credential level of assurance metadata.
    pub eudi_level_of_assurance: Option<String>,

    /// EUDI schema version metadata.
    pub eudi_schema_version: Option<String>,

    /// Ordered history of previous core CIDs.
    pub key_history: Vec<String>,

    /// JSON-layer verification methods, preserving caller-visible controller fields.
    pub verification_method: Vec<VerificationMethod>,

    /// Capability-invocation relationship references.
    pub capability_invocation: Vec<String>,

    /// Domain verification claims projected into the DID Document.
    pub domain_verification: Vec<DomainVerification>,

    /// Core attestations proving update-policy authorization.
    pub attestations: Vec<Attestation>,

    /// Optional did:me ES256 JWS CID proof.
    pub data_integrity_proof: Option<DataIntegrityProof>,
}

/// Project into a JSON DIDDocument.
///
/// Important semantics:
/// - controller list collapses to string when len==1
/// - prev is None if empty
/// - coreCbor is base64url(canonical_cbor)
/// - currentCore is the provided CID string
/// - services are projected from the canonical DAG-CBOR serviceEndpoint value
pub fn project_did_document(input: DocumentProjection<'_>) -> Result<DIDDocument, DidCoreError> {
    let core_cbor_bytes = input.core.canonical_cbor()?;
    let core_cbor_b64u = bytes_to_base64url(&core_cbor_bytes);

    let controller = if input.core.controller.len() == 1 {
        Controller::Single(input.core.controller[0].clone())
    } else {
        Controller::Multiple(input.core.controller.clone())
    };

    let prev = input.core.prev.clone();

    let services: Vec<Service> = input
        .core
        .services
        .iter()
        .map(|cs| {
            Ok(Service {
                id: cs.id.clone(),
                service_type: cs.service_type.clone(),
                service_endpoint: cbor_to_json_value(&cs.service_endpoint)?,
            })
        })
        .collect::<Result<Vec<_>, DidCoreError>>()?;

    let update_policy = Some(UpdatePolicy {
        allowed_verification_methods: input
            .core
            .update_policy
            .allowed_verification_methods
            .clone(),
        threshold: input.core.update_policy.threshold,
    });

    Ok(DIDDocument {
        context: default_context(),
        id: input.core.id.clone(),
        controller,

        also_known_as: input.also_known_as,

        sequence: input.core.sequence,
        prev,
        nonce: input
            .core
            .nonce
            .as_ref()
            .map(|nonce| bytes_to_base64url(nonce)),

        hardware_bound: input.hardware_bound,
        biometric_protected: input.biometric_protected,
        user_verification_method: input.user_verification_method,
        device_model: input.device_model,

        core_cbor: core_cbor_b64u,
        current_core: input.core_cid.to_string(),

        key_history: input.key_history,

        verification_method: input.verification_method,

        authentication: input.core.authentication.clone(),
        assertion_method: input.core.assertion.clone(),
        capability_invocation: input.capability_invocation,
        key_agreement: input.core.key_agreement.clone(),

        service: services,

        update_policy,

        attestations: input.attestations,

        data_integrity_proof: input.data_integrity_proof,

        domain_verification: input.domain_verification,
        eudi_level_of_assurance: input.eudi_level_of_assurance,
        eudi_schema_version: input.eudi_schema_version,
    })
}
