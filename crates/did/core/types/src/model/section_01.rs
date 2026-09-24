// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use core::fmt;

use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use zeroize::{Zeroize, ZeroizeOnDrop};

//
// ------------------------------------------------------------
// DID Document (JSON-facing, MUST be camelCase)
// ------------------------------------------------------------
//

// Clone is deliberate for immutable DID transition validation. Every clone is
// an owned identifying copy and therefore receives the same drop cleanup.
#[derive(Clone, Serialize, Deserialize, Default, PartialEq)]
#[serde(rename_all = "camelCase")]
/// DID document projection for did:me and eIDAS-oriented identity workflows.
pub struct DIDDocument {
    /// JSON-LD context entries for DID Core, Multikey, and did:me terms.
    #[serde(rename = "@context")]
    pub context: Vec<String>,

    /// DID subject identifier.
    pub id: String,

    /// Controller value as either a single DID or an ordered list of DIDs.
    pub controller: Controller,

    /// Additional identifiers associated with the DID subject.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub also_known_as: Vec<String>,

    /// did:me document sequence number.
    pub sequence: u64,

    /// Previous core CID for sequence numbers after genesis.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prev: Option<String>,

    /// Genesis nonce encoded for JSON transport.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,

    /// Whether the credential/key material is bound to hardware.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hardware_bound: Option<bool>,

    /// Whether biometric protection is asserted for the subject or device.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub biometric_protected: Option<bool>,

    /// Human-verification method identifier for wallet or issuer policy decisions.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_verification_method: Option<String>,

    /// Device model metadata when the DID document represents a hardware-backed device.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_model: Option<String>,

    /// Base64url-encoded canonical DAG-CBOR did:me core snapshot.
    pub core_cbor: String,

    /// CID of the canonical did:me core snapshot.
    pub current_core: String,

    /// Ordered historical core CIDs, excluding the current core.
    #[serde(default)]
    pub key_history: Vec<String>,

    /// Verification methods advertised by this DID document.
    #[serde(default)]
    pub verification_method: Vec<VerificationMethod>,

    /// Authentication relationship verification method references.
    #[serde(default)]
    pub authentication: Vec<String>,

    /// Assertion relationship verification method references.
    #[serde(default)]
    pub assertion_method: Vec<String>,

    /// Capability invocation relationship verification method references.
    #[serde(default)]
    pub capability_invocation: Vec<String>,

    /// Key agreement relationship verification method references.
    #[serde(default)]
    pub key_agreement: Vec<String>,

    /// Service endpoints published by this DID document.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub service: Vec<Service>,

    /// did:me update policy carried in the JSON projection.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub update_policy: Option<UpdatePolicy>,

    /// Core attestations proving controller key participation.
    #[serde(default)]
    pub attestations: Vec<Attestation>,

    /// Optional Data Integrity proof over the current core CID.
    #[serde(rename = "proof", skip_serializing_if = "Option::is_none")]
    pub data_integrity_proof: Option<DataIntegrityProof>,

    /// Domain verification claims linked to this DID document.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub domain_verification: Vec<DomainVerification>,

    /// eIDAS or EUDI level of assurance profile identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub eudi_level_of_assurance: Option<String>,

    /// EUDI schema or profile version associated with this projection.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub eudi_schema_version: Option<String>,
}

//
// ------------------------------------------------------------
// Controller (string | string[])
// ------------------------------------------------------------
//

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
/// DID Core controller value represented as either one DID or multiple DIDs.
pub enum Controller {
    /// Single-controller DID form.
    Single(String),

    /// Multi-controller DID form.
    Multiple(Vec<String>),
}

impl Default for Controller {
    fn default() -> Self {
        Controller::Single(String::new())
    }
}

//
// ------------------------------------------------------------
// Verification Method
// ------------------------------------------------------------
//

#[derive(Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
/// DID verification method entry.
pub struct VerificationMethod {
    /// Fragment identifier such as `#key-1`.
    pub id: String,

    /// Verification method type, currently expected to be `Multikey`.
    #[serde(rename = "type")]
    pub vm_type: String, // ALWAYS "Multikey"

    /// DID that controls this verification method.
    pub controller: String,

    /// Multibase-encoded public key material.
    pub public_key_multibase: String,

    /// Optional did:me algorithm string for this verification method.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub algorithm: Option<String>,
}

//
// ------------------------------------------------------------
// Service
// ------------------------------------------------------------
//

#[derive(Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
/// DID service endpoint entry.
pub struct Service {
    /// Service fragment identifier.
    pub id: String,

    /// DID service type.
    #[serde(rename = "type")]
    pub service_type: String,

    /// Service endpoint value preserved as JSON.
    pub service_endpoint: JsonValue,
}

//
// ------------------------------------------------------------
// Update Policy
// ------------------------------------------------------------
//

#[derive(Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
/// did:me update policy projected into the DID document.
pub struct UpdatePolicy {
    /// Verification method references allowed to authorize updates.
    pub allowed_verification_methods: Vec<String>,

    /// Optional signature threshold; missing means one required signature.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub threshold: Option<u64>,
}

impl UpdatePolicy {
    /// Return the effective threshold after applying the did:me default.
    pub fn effective_threshold(&self) -> u64 {
        self.threshold.unwrap_or(1)
    }
}

//
// ------------------------------------------------------------
// Attestation
// ------------------------------------------------------------
//

#[derive(Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
/// Signature over the canonical did:me core snapshot.
pub struct Attestation {
    /// Algorithm identifier used for the signature.
    pub alg: String,

    /// Verification method reference that produced the signature.
    pub vm: String,

    /// Base64url-encoded signature bytes.
    pub sig: String,
}

//
// ------------------------------------------------------------
// Data Integrity Proof
// ------------------------------------------------------------
//

#[derive(Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
/// Data Integrity proof embedded as `proof` in a DID document.
pub struct DataIntegrityProof {
    /// Proof type, normally `DataIntegrityProof`.
    #[serde(rename = "type")]
    pub proof_type: String,

    /// Cryptosuite identifier such as `es256-jws-cid-2025`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cryptosuite: Option<String>,

    /// Proof purpose, for did:me CID proofs this must be `assertionMethod`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof_purpose: Option<String>,

    /// Verification method reference used to verify the proof.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verification_method: Option<String>,

    /// RFC3339 creation timestamp supplied by the host environment.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created: Option<String>,

    /// Compact JWS carrying the signed current core CID payload.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jws: Option<String>,
}

//
// ------------------------------------------------------------
// Domain Verification
// ------------------------------------------------------------
//

#[derive(Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
/// Domain verification claim for a DID document.
pub struct DomainVerification {
    /// Verification claim type from the did:me JSON profile.
    #[serde(rename = "type")]
    pub verification_type: String,

    /// Verification method name, currently `dns` or `wellknown`.
    pub method: String,

    /// DNS domain being verified.
    pub domain: String,

    /// DNS TXT binding when `method` is `dns`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dns: Option<DNSBinding>,

    /// HTTPS well-known binding when `method` is `wellknown`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wellknown: Option<WellKnownBinding>,
}

#[derive(Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
/// DNS TXT binding for a domain verification claim.
pub struct DNSBinding {
    /// TXT record name to query.
    pub record_name: String,

    /// Expected TXT record value.
    pub txt_value: String,
}

#[derive(Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
/// HTTPS well-known binding for a domain verification claim.
pub struct WellKnownBinding {
    /// Well-known URI or absolute HTTPS URL to fetch.
    pub uri: String,

    /// Expected DID content in the fetched well-known response.
    pub content: String,
}

impl Zeroize for DIDDocument {
    fn zeroize(&mut self) {
        zeroize_strings(&mut self.context);
        self.id.zeroize();
        match &mut self.controller {
            Controller::Single(controller) => controller.zeroize(),
            Controller::Multiple(controllers) => zeroize_strings(controllers),
        }
        zeroize_strings(&mut self.also_known_as);
        self.sequence = 0;
        self.prev.zeroize();
        self.nonce.zeroize();
        self.hardware_bound = None;
        self.biometric_protected = None;
        self.user_verification_method.zeroize();
        self.device_model.zeroize();
        self.core_cbor.zeroize();
        self.current_core.zeroize();
        zeroize_strings(&mut self.key_history);

        for method in &mut self.verification_method {
            method.zeroize();
        }
        self.verification_method.clear();
        zeroize_strings(&mut self.authentication);
        zeroize_strings(&mut self.assertion_method);
        zeroize_strings(&mut self.capability_invocation);
        zeroize_strings(&mut self.key_agreement);

        for service in &mut self.service {
            service.zeroize();
        }
        self.service.clear();

        if let Some(policy) = &mut self.update_policy {
            policy.zeroize();
        }
        self.update_policy = None;

        for attestation in &mut self.attestations {
            attestation.zeroize();
        }
        self.attestations.clear();

        if let Some(proof) = &mut self.data_integrity_proof {
            proof.zeroize();
        }
        self.data_integrity_proof = None;

        for verification in &mut self.domain_verification {
            verification.zeroize();
        }
        self.domain_verification.clear();
        self.eudi_level_of_assurance.zeroize();
        self.eudi_schema_version.zeroize();
    }
}

impl Zeroize for Controller {
    fn zeroize(&mut self) {
        match self {
            Self::Single(controller) => controller.zeroize(),
            Self::Multiple(controllers) => zeroize_strings(controllers),
        }
    }
}

impl Zeroize for VerificationMethod {
    fn zeroize(&mut self) {
        self.id.zeroize();
        self.vm_type.zeroize();
        self.controller.zeroize();
        self.public_key_multibase.zeroize();
        self.algorithm.zeroize();
    }
}

impl Zeroize for Service {
    fn zeroize(&mut self) {
        self.id.zeroize();
        self.service_type.zeroize();
        zeroize_json(&mut self.service_endpoint);
    }
}

impl Zeroize for UpdatePolicy {
    fn zeroize(&mut self) {
        zeroize_strings(&mut self.allowed_verification_methods);
        self.threshold = None;
    }
}

impl Zeroize for Attestation {
    fn zeroize(&mut self) {
        self.alg.zeroize();
        self.vm.zeroize();
        self.sig.zeroize();
    }
}

impl Zeroize for DataIntegrityProof {
    fn zeroize(&mut self) {
        self.proof_type.zeroize();
        self.cryptosuite.zeroize();
        self.proof_purpose.zeroize();
        self.verification_method.zeroize();
        self.created.zeroize();
        self.jws.zeroize();
    }
}
