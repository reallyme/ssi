// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::canonical::Canonical;
use crate::canonical::{json_to_cbor_value, normalize_json_value};
use crate::core::{
    CanonicalService, CoreVerificationMethod, DidCore, UpdatePolicy as CoreUpdatePolicy,
};
use crate::document::{project_did_document, DocumentProjection};
use crate::error::{CanonicalStateViolation, DidCoreError};
use crate::hashing::compute_core_cid;
use crate::signing::sign_core;

use core::str::FromStr;
use identity_core_primitives::algorithm_map::alg_to_did_alg_str;
use identity_core_primitives::Algorithm;

use reallyme_did_types::{
    Attestation as JsonAttestation, DIDDocument, DNSBinding, DataIntegrityProof,
    DomainVerification, VerificationMethod as JsonVerificationMethod, WellKnownBinding,
};

// helpers
fn vm_algorithm(id: &str, vms: &[CoreVerificationMethod]) -> Option<Algorithm> {
    vms.iter().find(|vm| vm.id == id).map(|vm| vm.algorithm)
}

fn canonicalize_projection_verification_methods(
    input: &[JsonVerificationMethod],
    core_keys: &[CoreVerificationMethod],
) -> Result<Vec<JsonVerificationMethod>, DidCoreError> {
    let mut out = Vec::with_capacity(input.len());

    for vm in input {
        let core_vm = core_keys.iter().find(|core_vm| core_vm.id == vm.id).ok_or(
            DidCoreError::InvalidCanonicalState(
                CanonicalStateViolation::InvalidCreatePreconditions,
            ),
        )?;

        let mut projected = vm.clone();
        projected.vm_type = "Multikey".into();
        projected.algorithm = Some(alg_to_did_alg_str(core_vm.algorithm).to_owned());
        out.push(projected);
    }

    out.sort_by(|a, b| a.id.as_bytes().cmp(b.id.as_bytes()));
    Ok(out)
}

/// Developer-facing input (Rust equivalent of TS CreateOptions).
#[derive(Debug, Clone)]
pub struct CreateOptions {
    /// Requested DID identifier, replaced with derived genesis DID for sequence one.
    pub id: String,

    /// DID controllers.
    pub controller: Vec<String>,

    /// DID sequence number.
    pub sequence: u64,

    /// Previous core CID for non-genesis creation.
    pub prev: Option<String>,

    /// Verification methods supplied by the caller or profile builder.
    pub controller_keys: Vec<JsonVerificationMethod>,

    /// Authentication relationship references.
    pub authentication: Vec<String>,

    /// Assertion relationship references.
    pub assertion: Vec<String>,

    /// Capability invocation relationship references.
    pub invocation: Vec<String>,

    /// Key agreement relationship references.
    pub key_agreement: Vec<String>,

    /// Services to project into the DID document and canonical core.
    pub services: Vec<ServiceInput>,

    /// Update-policy allowed verification methods.
    pub allowed_verification_methods: Vec<String>,

    /// Optional update-policy threshold.
    pub threshold: Option<u64>,

    /// Genesis nonce bytes.
    pub nonce: Option<Vec<u8>>,

    /// Domain verification claims to derive.
    pub domain_verification: Vec<DomainVerificationInput>,

    /// Additional identifiers to publish in `alsoKnownAs`.
    pub also_known_as: Vec<String>,

    /// Hardware-bound metadata.
    pub hardware_bound: Option<bool>,

    /// Biometric-protection metadata.
    pub biometric_protected: Option<bool>,

    /// User verification method metadata.
    pub user_verification_method: Option<String>,

    /// Device model metadata.
    pub device_model: Option<String>,

    /// Host-supplied proof creation timestamp.
    pub created: Option<String>,
}

/// Service endpoint input before canonicalization.
#[derive(Debug, Clone)]
pub struct ServiceInput {
    /// Service fragment identifier.
    pub id: String,

    /// DID service type.
    pub service_type: String,

    /// JSON service endpoint to canonicalize into the core.
    pub service_endpoint: serde_json::Value,
}

/// Built-in domain verification derivation presets.
#[derive(Debug, Clone)]
pub enum DomainVerificationPreset {
    /// Generate the default did:me DNS or well-known binding.
    DidMeDefault,

    /// Generate a DID configuration well-known binding.
    DidConfiguration,
}

/// Domain verification input before binding derivation.
#[derive(Debug, Clone)]
pub struct DomainVerificationInput {
    /// Method name, currently `dns` or `wellknown`.
    pub method: String, // "dns" | "wellknown"

    /// Domain to bind to the DID document.
    pub domain: String,

    /// Optional derivation preset.
    pub preset: Option<DomainVerificationPreset>,
}

/// Result of DID creation.
#[derive(Debug, Clone)]
pub struct CreateResult {
    /// Projected DID document.
    pub document: DIDDocument,

    /// Canonical core bytes.
    pub core_cbor: Vec<u8>,

    /// CID of the canonical core.
    pub core_cid: String,
}

fn map_services(in_services: &[ServiceInput]) -> Result<Vec<CanonicalService>, DidCoreError> {
    let mut out = Vec::new();

    for s in in_services {
        let normalized = normalize_json_value(&s.service_endpoint);
        let service_endpoint = json_to_cbor_value(&normalized)?;

        out.push(CanonicalService {
            id: s.id.clone(),
            service_type: s.service_type.clone(),
            service_endpoint,
        });
    }

    Ok(out)
}

fn autopopulate_domain_verification(
    opts: &CreateOptions,
) -> Result<Vec<DomainVerification>, DidCoreError> {
    let mut out = Vec::new();

    for dv in &opts.domain_verification {
        let method = dv.method.to_lowercase();

        match (method.as_str(), dv.preset.as_ref()) {
            ("dns", Some(DomainVerificationPreset::DidMeDefault)) => {
                out.push(DomainVerification {
                    verification_type: "DnsTxtVerification".into(),
                    method: "dns".into(),
                    domain: dv.domain.clone(),
                    dns: Some(DNSBinding {
                        record_name: "_did".into(),
                        txt_value: opts.id.clone(),
                    }),
                    wellknown: None,
                });
            }

            ("dns", Some(DomainVerificationPreset::DidConfiguration)) => {
                out.push(DomainVerification {
                    verification_type: "DnsTxtVerification".into(),
                    method: "dns".into(),
                    domain: dv.domain.clone(),
                    dns: Some(DNSBinding {
                        record_name: "_did".into(),
                        txt_value: opts.id.clone(),
                    }),
                    wellknown: None,
                });
            }

            ("wellknown", Some(DomainVerificationPreset::DidMeDefault)) => {
                out.push(DomainVerification {
                    verification_type: "HttpsWellKnownVerification".into(),
                    method: "wellknown".into(),
                    domain: dv.domain.clone(),
                    dns: None,
                    wellknown: Some(WellKnownBinding {
                        uri: "/.well-known/did-configuration.json".into(),
                        content: opts.id.clone(),
                    }),
                });
            }

            ("wellknown", Some(DomainVerificationPreset::DidConfiguration)) => {
                out.push(DomainVerification {
                    verification_type: "HttpsWellKnownVerification".into(),
                    method: "wellknown".into(),
                    domain: dv.domain.clone(),
                    dns: None,
                    wellknown: Some(WellKnownBinding {
                        uri: "/.well-known/did-configuration.json".into(),
                        content: opts.id.clone(),
                    }),
                });
            }

            _ => {
                return Err(DidCoreError::InvalidCanonicalState(
                    CanonicalStateViolation::UnsupportedDomainVerification,
                ))
            }
        }
    }

    Ok(out)
}
