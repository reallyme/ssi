// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Presentation container independent of delivery protocol.
///
/// Presentation models deliberately do not implement Serde. Protobuf is the
/// canonical transport contract; ProtoJSON interoperability is provided only
/// by the bounded generated-message codec.
#[derive(PartialEq, Eq)]
#[non_exhaustive]
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
#[derive(PartialEq, Eq)]
pub struct MdocPresentation {
    /// CBOR bytes of an ISO 18013-5 `DeviceResponse`.
    pub device_response: Vec<u8>,

    /// Optional hash of the signed credential envelope being presented.
    pub envelope_hash: Option<[u8; 32]>,

    /// Optional mdoc document type.
    pub doc_type: Option<String>,
}

/// SD-JWT VC presentation transport payload.
#[derive(PartialEq, Eq)]
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

/// The semantic statement carried by a zero-knowledge presentation.
///
/// The variant is a routing hint, not evidence of proof validity. A verifier
/// must authenticate the proof package and bind its verified profile to this
/// variant before using any disclosures or status facts.
#[derive(PartialEq, Eq)]
#[non_exhaustive]
pub enum ZkPresentation {
    /// Claim from one issuer credential.
    Credential(ZkCredentialPresentation),
    /// Claim authorized through one persona.
    Persona(ZkPersonaPresentation),
    /// Claims from two credentials joined by an assured private root.
    CommonRoot(ZkCommonRootPresentation),
}

/// Whether persona ownership is kept private or intentionally exposed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ZkPersonaMode {
    /// Persona ownership remains hidden in the proof.
    Private,
    /// Persona ownership is publicly bound by the proof.
    Public,
}

/// Whether a presentation proof is bound directly to the active request or
/// prepared earlier and authenticated with a fresh holder signature.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ZkPresentationProofMode {
    /// Circuit proof directly binds the active verifier request.
    RequestBoundProof,
    /// Prepared circuit proof is joined to current state and live key control.
    PreparedProof,
}

impl ZkPresentation {
    /// Freshness values that the verified proof must bind.
    pub fn freshness(&self) -> &PresentationFreshness {
        match self {
            Self::Credential(value) => &value.freshness,
            Self::Persona(value) => &value.freshness,
            Self::CommonRoot(value) => &value.freshness,
        }
    }

    /// Claimed disclosures, usable only after the proof has been verified.
    pub fn disclosures(&self) -> &[ClaimDisclosure] {
        match self {
            Self::Credential(value) => &value.disclosures,
            Self::Persona(value) => &value.disclosures,
            Self::CommonRoot(value) => &value.disclosures,
        }
    }

    /// Return the binding mode required by the selected proof statement.
    pub fn proof_mode(&self) -> ZkPresentationProofMode {
        match self {
            Self::Credential(_) | Self::CommonRoot(_) => ZkPresentationProofMode::RequestBoundProof,
            Self::Persona(value) => value.evidence.proof_mode(),
        }
    }
}

/// Single-credential ZK presentation with an explicit credential reference.
#[derive(PartialEq, Eq)]
pub struct ZkCredentialPresentation {
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

/// Persona-authorized presentation. Subject and status openings are private
/// witness inputs; the public package carries only proof and public inputs.
#[derive(PartialEq, Eq)]
pub struct ZkPersonaPresentation {
    /// Freshness and audience binding.
    pub freshness: PresentationFreshness,
    /// Private or public persona ownership statement.
    pub mode: ZkPersonaMode,
    /// Claim disclosures authenticated by the verified proof.
    pub disclosures: Vec<ClaimDisclosure>,
    /// Exactly one request-bound or prepared evidence form.
    pub evidence: ZkPersonaEvidence,
}

/// Mutually exclusive proof and freshness mechanisms for one persona claim.
#[derive(PartialEq, Eq)]
#[non_exhaustive]
pub enum ZkPersonaEvidence {
    /// Opaque proof package whose public inputs bind the active request.
    RequestBound {
        /// Canonical proof package with the active request as public input.
        proof_package: Vec<u8>,
    },
    /// Prepared proof joined to signed status and live holder authentication.
    Prepared(ZkPreparedPersonaEvidence),
}

impl ZkPersonaEvidence {
    /// Return the proof's required presentation binding mode.
    pub fn proof_mode(&self) -> ZkPresentationProofMode {
        match self {
            Self::RequestBound { .. } => ZkPresentationProofMode::RequestBoundProof,
            Self::Prepared(_) => ZkPresentationProofMode::PreparedProof,
        }
    }
}

/// Prepared persona evidence bound to a current status snapshot and verified
/// request by a holder signature. The holder key is a stable persona key in
/// public mode and a reserved one-time key in private mode. These bytes are
/// transport data only; a consumer must verify the exact ZK profile, issuer
/// credential, status, signature, and request before accepting a disclosure.
#[derive(PartialEq, Eq)]
pub struct ZkPreparedPersonaEvidence {
    /// Canonical four-proof ZkPreparedCredentialEvidenceV1 package. Each proof
    /// is verified under its own pinned source artifact and joined to the same
    /// credential and selected holder key.
    pub prepared_evidence_package: Vec<u8>,
    /// Canonical ZkPreparedRawProofPackage for current issuer status.
    pub current_state_package: Vec<u8>,
    /// Canonical authenticated request constructed by the protocol adapter.
    pub verifier_request: Vec<u8>,
    /// Canonical presentation-authentication transcript.
    pub holder_authentication: Vec<u8>,
    /// P-256 holder key exposed by the verified proof.
    pub holder_public_key: [u8; 64],
    /// Signature by the exposed holder key over the transcript digest.
    pub holder_signature: [u8; 64],
}

/// Two credentials linked through the same assured private root. The package
/// carries proof data, never the private credential or root openings.
#[derive(PartialEq, Eq)]
pub struct ZkCommonRootPresentation {
    /// Freshness and audience binding.
    pub freshness: PresentationFreshness,
    /// Private or public presenting persona ownership statement.
    pub mode: ZkPersonaMode,
    /// Claim disclosures authenticated by the verified proof.
    pub disclosures: Vec<ClaimDisclosure>,
    /// Opaque, versioned ZK proof package bytes.
    pub proof_package: Vec<u8>,
}

/// Freshness and audience-binding inputs for a presentation.
#[derive(PartialEq, Eq)]
pub struct PresentationFreshness {
    /// Verifier challenge or nonce.
    pub challenge: [u8; 32],

    /// Hash of the intended verifier, audience, origin, or relying party.
    pub audience_hash: [u8; 32],

    /// Expiration time as Unix seconds.
    pub expiry_unix: u64,
}

/// Reference to the credential being presented.
#[derive(PartialEq, Eq)]
pub struct CredentialReference {
    /// Hash of canonical VC bytes or the signed credential envelope.
    pub envelope_hash: [u8; 32],

    /// Issuer DID expected for the credential.
    pub issuer_did: String,

    /// Status pointer snapshot.
    pub status: CredentialStatusRef,
}

/// Minimal credential status reference.
#[derive(PartialEq, Eq)]
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
#[non_exhaustive]
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
#[non_exhaustive]
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
#[derive(PartialEq, Eq)]
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
#[derive(PartialEq, Eq)]
pub struct Range {
    /// Minimum accepted value.
    pub min: u64,

    /// Maximum accepted value.
    pub max: u64,
}

/// Set of accepted byte-string values.
#[derive(PartialEq, Eq)]
pub struct ValueSet {
    /// Accepted values.
    pub values: Vec<Vec<u8>>,
}

/// Exact audited proving and verification suite for a ZK proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ZkProofSuite {
    /// Barretenberg UltraHonk with Keccak transcript, ZK enabled, and no IPA.
    BarretenbergUltraHonkKeccakZkNoIpa,
}

/// Zero-knowledge proof payload and verification metadata.
#[derive(PartialEq, Eq)]
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
#[derive(PartialEq, Eq)]
pub struct QeaaVerifierHints {
    /// Whether QEAA evidence is required.
    pub required: bool,

    /// Optional hash of the audit report expected by the verifier.
    pub audit_report_hash: Option<[u8; 32]>,

    /// Maximum acceptable status age in seconds.
    pub max_status_age_seconds: u32,
}
