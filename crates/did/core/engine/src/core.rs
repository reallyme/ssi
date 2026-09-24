// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0
use identity_core_primitives::Algorithm;

/// Canonical DID core object.
///
/// This mirrors the TS `coreEnvelope`.
/// It contains NO proofs, NO signatures, NO envelopes.
#[derive(Debug, Clone)]
pub struct DidCore {
    /// DID identifier bound to this core state.
    pub id: String,

    /// Monotonic did:me sequence number.
    pub sequence: u64,

    /// Identifier-binding entropy. Present only for the genesis core.
    pub nonce: Option<Vec<u8>>,

    /// Always an array; never collapsed.
    pub controller: Vec<String>,

    /// Controller verification methods committed into the core.
    pub controller_keys: Vec<CoreVerificationMethod>,

    /// Authentication relationship references.
    pub authentication: Vec<String>,

    /// Assertion relationship references.
    pub assertion: Vec<String>,

    /// Key agreement relationship references.
    pub key_agreement: Vec<String>,

    /// Canonical service entries committed into the core.
    pub services: Vec<CanonicalService>,

    /// Update policy committed into the core.
    pub update_policy: UpdatePolicy,

    /// Previous core CID for non-genesis sequence numbers.
    pub prev: Option<String>,
}

/// Verification method committed into the canonical did:me core.
#[derive(Debug, Clone)]
pub struct CoreVerificationMethod {
    /// Verification method fragment identifier.
    pub id: String,

    /// Verification method type, currently `Multikey`.
    pub vm_type: String, // "Multikey"

    /// Semantic algorithm used by this verification method.
    pub algorithm: Algorithm,

    /// Multibase-encoded public key material.
    pub public_key_multibase: String,
}

/// Service endpoint represented in canonical CBOR form.
#[derive(Debug, Clone)]
pub struct CanonicalService {
    /// Service fragment identifier.
    pub id: String,

    /// DID service type.
    pub service_type: String,

    /// Canonical CBOR service endpoint value.
    pub service_endpoint: reallyme_codec::cbor::CborValue,
}

/// did:me update policy committed into canonical core state.
#[derive(Debug, Clone)]
pub struct UpdatePolicy {
    /// Verification method references allowed to authorize updates.
    pub allowed_verification_methods: Vec<String>,

    /// Optional update threshold; missing means one required signature.
    pub threshold: Option<u64>,
}

impl UpdatePolicy {
    /// Return the effective threshold after applying the did:me default.
    pub fn effective_threshold(&self) -> u64 {
        self.threshold.unwrap_or(1)
    }
}
