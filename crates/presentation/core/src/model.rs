// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Presentation container independent of delivery protocol.
///
/// Presentation models deliberately do not implement Serde. Protobuf is the
/// canonical transport contract; ProtoJSON interoperability is provided only
/// by the bounded generated-message codec.
#[derive(Clone, PartialEq, Eq)]
pub enum Presentation {
    /// Zero-knowledge presentation with semantic disclosures and proof bytes.
    Zk(Box<ZkPresentation>),

    /// SD-JWT VC presentation with disclosures and optional key binding JWT.
    SdJwtVc(Box<SdJwtVcPresentation>),

    /// ISO 18013-5 mdoc presentation.
    Mdoc(Box<MdocPresentation>),
}

/// Opaque mdoc presentation transport payload.
///
/// The VP layer does not verify `issuerAuth` or `deviceAuth`; mdoc verification
/// belongs in the mdoc envelope layer so the presentation core stays reusable.
#[derive(Clone, PartialEq, Eq)]
pub struct MdocPresentation {
    /// CBOR bytes of an ISO 18013-5 `DeviceResponse`.
    pub device_response: Vec<u8>,

    /// Optional hash of the signed credential envelope being presented.
    pub envelope_hash: Option<[u8; 32]>,

    /// Optional mdoc document type.
    pub doc_type: Option<String>,
}

/// SD-JWT VC presentation transport payload.
#[derive(Clone, PartialEq, Eq)]
pub struct SdJwtVcPresentation {
    /// Compact SD-JWT issuance or presentation string.
    pub sd_jwt: String,

    /// Base64url disclosure strings carried with the presentation.
    pub disclosures: Vec<String>,

    /// Optional key-binding JWT.
    pub kb_jwt: Option<String>,

    /// Optional Verifiable Credential Type hint.
    pub vct: Option<String>,

    /// Optional hash of the signed credential envelope being presented.
    pub envelope_hash: Option<[u8; 32]>,
}

/// Semantic zero-knowledge presentation.
#[derive(Clone, PartialEq, Eq)]
pub struct ZkPresentation {
    /// Freshness and audience binding.
    pub freshness: PresentationFreshness,

    /// Credential reference proved by this presentation.
    pub credential: CredentialReference,

    /// Claim disclosures satisfied by the proof.
    pub disclosures: Vec<ClaimDisclosure>,

    /// Concrete proof payload and verification-key metadata.
    pub zk_proof: ZkProof,

    /// Optional QEAA verifier hints.
    pub qeaa: Option<QeaaVerifierHints>,
}

/// Freshness and audience-binding inputs for a presentation.
#[derive(Clone, PartialEq, Eq)]
pub struct PresentationFreshness {
    /// Verifier challenge or nonce.
    pub challenge: [u8; 32],

    /// Hash of the intended verifier, audience, origin, or relying party.
    pub audience_hash: [u8; 32],

    /// Expiration time as Unix seconds.
    pub expiry_unix: u64,
}

/// Reference to the credential being presented.
#[derive(Clone, PartialEq, Eq)]
pub struct CredentialReference {
    /// Hash of canonical VC bytes or the signed credential envelope.
    pub envelope_hash: [u8; 32],

    /// Issuer DID expected for the credential.
    pub issuer_did: String,

    /// Status pointer snapshot.
    pub status: CredentialStatusRef,
}

/// Minimal credential status reference.
#[derive(Clone, PartialEq, Eq)]
pub struct CredentialStatusRef {
    /// Status-list URL.
    pub status_list_url: String,

    /// Status-list identifier.
    pub status_list_id: [u8; 32],

    /// Credential index in the status list.
    pub status_list_index: u64,

    /// Status purpose.
    pub purpose: StatusPurpose,
}

/// Credential status purpose.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StatusPurpose {
    /// Status purpose was not specified.
    Unspecified,

    /// Revocation status.
    Revocation,

    /// Suspension status.
    Suspension,
}

/// Claim disclosure mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DisclosureMode {
    /// Disclosure mode was not specified.
    Unspecified,

    /// Claim is hidden.
    Hidden,

    /// Claim value is revealed.
    Reveal,

    /// Claim must equal the supplied value.
    Eq,

    /// Claim must be greater than or equal to the threshold.
    Gte,

    /// Claim must be less than or equal to the threshold.
    Lte,

    /// Claim must fall within a closed range.
    Range,

    /// Claim must be a member of the supplied set.
    MemberOfSet,
}

/// Disclosure request or satisfied disclosure for a single claim.
#[derive(Clone, PartialEq, Eq)]
pub struct ClaimDisclosure {
    /// Dot/path-like claim selector.
    pub claim_path: String,

    /// Disclosure mode.
    pub mode: DisclosureMode,

    /// Revealed value bytes when `mode` is `Reveal` or `Eq`.
    pub revealed_value: Option<Vec<u8>>,

    /// Threshold used by comparison modes.
    pub threshold: Option<u64>,

    /// Closed range used by `DisclosureMode::Range`.
    pub range: Option<Range>,

    /// Value set used by `DisclosureMode::MemberOfSet`.
    pub set: Option<ValueSet>,
}

/// Inclusive numeric range.
#[derive(Clone, PartialEq, Eq)]
pub struct Range {
    /// Minimum accepted value.
    pub min: u64,

    /// Maximum accepted value.
    pub max: u64,
}

/// Set of accepted byte-string values.
#[derive(Clone, PartialEq, Eq)]
pub struct ValueSet {
    /// Accepted values.
    pub values: Vec<Vec<u8>>,
}

/// Exact audited proving and verification suite for a ZK proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ZkProofSuite {
    /// Barretenberg UltraHonk with Keccak transcript, ZK enabled, and no IPA.
    BarretenbergUltraHonkKeccakZkNoIpa,
}

/// Zero-knowledge proof payload and verification metadata.
#[derive(Clone, PartialEq, Eq)]
pub struct ZkProof {
    /// Circuit identifier.
    pub circuit_id: String,

    /// Circuit version.
    pub circuit_version: String,

    /// Verification-key identifier.
    pub vk_id: String,

    /// Opaque proof bytes.
    pub proof_bytes: Vec<u8>,

    /// Circuit-defined public inputs.
    pub public_inputs: BTreeMap<String, Vec<u8>>,

    /// Exact proof system and transcript configuration.
    pub proof_suite: ZkProofSuite,

    /// SHA-256 identity of the canonical prover/verifier artifact manifest.
    pub artifact_manifest_sha256: [u8; 32],
}

/// QEAA verifier hints.
#[derive(Clone, PartialEq, Eq)]
pub struct QeaaVerifierHints {
    /// Whether QEAA evidence is required.
    pub required: bool,

    /// Optional hash of the audit report expected by the verifier.
    pub audit_report_hash: Option<[u8; 32]>,

    /// Maximum acceptable status age in seconds.
    pub max_status_age_seconds: u32,
}
