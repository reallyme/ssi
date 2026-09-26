// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::collections::BTreeMap;

use crypto_core::Algorithm as CryptoAlg;
use crypto_signer::{DispatchSigner, Signer};
use reallyme_credential_audit::QeaaCompliance;
use reallyme_credential_claims::CLAIM_COMMITMENT_VALUE_ENCODING;
use reallyme_crypto::{
    core::RngOutputKind, operations::random::fill_bytes as fill_secure_random,
    p256::p256_ecdsa_der_to_jose_signature, secp256k1::secp256k1_ecdsa_der_to_jose_signature,
    sha2::digest as sha2_256_digest,
};
use zeroize::Zeroizing;

/// Minimum salt length accepted by ReallyMe Merkle claim commitments.
pub const MIN_COMMITMENT_SALT_BYTES: u32 = 16;
/// Maximum salt length accepted by ReallyMe Merkle claim commitments.
pub const MAX_COMMITMENT_SALT_BYTES: u32 = 64;
/// Absolute maximum canonical value length accepted by a commitment.
pub const MAX_COMMITMENT_VALUE_BYTES: u32 = 1_048_576;
/// Absolute maximum number of claims accepted by a commitment tree.
pub const MAX_COMMITMENT_CLAIMS: usize = 4_096;

use crate::committed::{
    canonical::canonical_credential_bytes,
    error::VcError,
    model::{
        AssuranceLevel, ClaimOpening, ClaimsCommitment, CommitmentLimits, CredentialAlgorithm,
        CredentialEnvelope, CredentialKind, CredentialStatus, CredentialSubject, DomainTags,
        HolderBinding, MerkleTreeInfo, PartyReference, PublicKeyRef, Signature,
        SubjectPrivateBundle,
    },
    proof_binding::{p256_coordinates, CredentialProofBinding, CREDENTIAL_PROOF_BINDING_VERSION},
};

/// Input for issuing a credential (public envelope).
#[derive(Debug)]
pub struct IssueInput {
    pub kind: CredentialKind,
    pub profile_id: String,
    pub assurance: AssuranceLevel,

    pub issuer_reference: PartyReference,
    /// Public verification key attached to the issuer signature.
    pub issuer_verification_key: PublicKeyRef,
    pub issuer_country: String,

    /// UTC seconds since epoch.
    pub valid_from: i64,
    pub valid_until: i64,

    pub status: CredentialStatus,

    pub subject: CredentialSubject,

    /// Commitment profile.
    pub claimset_id: String,
    pub domain_tags: DomainTags,
    pub limits: CommitmentLimits,

    /// Optional QEAA metadata.
    pub qeaa_compliance: Option<QeaaCompliance>,
}

/// Result of issuance: public envelope + subject-private bundle.
#[derive(Debug)]
pub struct IssueResult {
    pub envelope: CredentialEnvelope,
    pub subject_bundle: SubjectPrivateBundle,
    /// Optional proof binding emitted atomically with P-256 credentials whose
    /// holder is also bound to a P-256 key.
    pub proof_binding: Option<CredentialProofBinding>,
}

/// Minimal signing boundary used by host keystores, HSMs, and remote signers.
pub trait CredentialPayloadSigner {
    /// Signature algorithm selected by the issuer key.
    fn algorithm(&self) -> CryptoAlg;

    /// Sign the canonical public credential payload.
    fn sign_payload(&self, payload: &[u8]) -> Result<Vec<u8>, VcError>;
}

struct CryptoSignerAdapter<'a> {
    signer: &'a dyn Signer,
}

impl CredentialPayloadSigner for CryptoSignerAdapter<'_> {
    fn algorithm(&self) -> CryptoAlg {
        self.signer.alg()
    }

    fn sign_payload(&self, payload: &[u8]) -> Result<Vec<u8>, VcError> {
        self.signer
            .sign(payload)
            .map_err(|_| VcError::InvalidCredential)
    }
}

/// Issue a credential using the "static Merkle root" model.
///
/// - Values are encoded using a deterministic JSON canonicalization compatible with the TS JCS rules
///   (object keys sorted recursively; arrays preserved; primitives unchanged).
/// - Inner digest: SHA-256( CLM_TAG || u64be(len(value)) || value || salt )
/// - Leaf digest: SHA-256( LEAF_TAG || SHA-256(path_utf8) || inner_digest )
/// - Node digest: SHA-256( NODE_TAG || left || right )
/// - Tree padded to next power-of-two by repeating last leaf.
///
/// Signing:
/// - Signature input bytes = canonical CBOR bytes of the envelope (excluding its signature)
/// - ECDSA signatures are stored raw r||s (64 bytes); DER accepted and normalized.
///
/// Returns:
/// - CredentialEnvelope (public)
/// - SubjectPrivateBundle (private openings + paths)
pub fn issue_credential<R: SaltRng>(
    input: IssueInput,
    claims: &BTreeMap<String, serde_json::Value>,
    issuer_crypto_alg: CryptoAlg,
    issuer_private_key: &[u8],
    rng: &mut R,
) -> Result<IssueResult, VcError> {
    let signer = DispatchSigner::new(issuer_crypto_alg, issuer_private_key.to_vec());
    issue_credential_with_signer(input, claims, &signer, rng)
}

/// Issue a credential using an abstract signer (HSM/QSCD/remote signing friendly).
///
/// This function is identical to `issue_credential` except that it does not require the SDK
/// to hold private key bytes.
pub fn issue_credential_with_signer<R: SaltRng>(
    input: IssueInput,
    claims: &BTreeMap<String, serde_json::Value>,
    signer: &dyn Signer,
    rng: &mut R,
) -> Result<IssueResult, VcError> {
    issue_credential_with_payload_signer(input, claims, &CryptoSignerAdapter { signer }, rng)
}

/// Issue through the narrow ReallyMe host signing boundary.
pub fn issue_credential_with_payload_signer<R: SaltRng + ?Sized>(
    input: IssueInput,
    claims: &BTreeMap<String, serde_json::Value>,
    signer: &dyn CredentialPayloadSigner,
    rng: &mut R,
) -> Result<IssueResult, VcError> {
    // Basic hygiene: `valid_until` is exclusive, so an empty window is rejected
    // consistently with public envelope validation.
    if input.valid_until <= input.valid_from {
        return Err(VcError::InvalidCredential);
    }
    if input.limits.salt_len < MIN_COMMITMENT_SALT_BYTES
        || input.limits.salt_len > MAX_COMMITMENT_SALT_BYTES
        || input.limits.max_value_len == 0
        || input.limits.max_value_len > MAX_COMMITMENT_VALUE_BYTES
        || claims.len() > MAX_COMMITMENT_CLAIMS
    {
        return Err(VcError::InvalidCredential);
    }

    // 1) Deterministic claim ordering
    let mut names: Vec<String> = claims.keys().cloned().collect();
    names.sort();

    if names.is_empty() {
        return Err(VcError::InvalidCredential);
    }

    // 2) Build leaves + openings data
    let clm_tag = input.domain_tags.clm.as_bytes();
    let leaf_tag = input.domain_tags.leaf.as_bytes();
    let node_tag = input.domain_tags.node.as_bytes();

    let salt_len =
        usize::try_from(input.limits.salt_len).map_err(|_| VcError::InvalidCredential)?;
    let max_value_len =
        usize::try_from(input.limits.max_value_len).map_err(|_| VcError::InvalidCredential)?;

    let mut leaf_hashes: Vec<[u8; 32]> = Vec::with_capacity(names.len());
    let mut openings: Vec<ClaimOpening> = Vec::with_capacity(names.len());

    for (idx, name) in names.iter().enumerate() {
        assert_safe_claim_name(name)?;

        let v = claims.get(name).ok_or(VcError::InvalidCredential)?;

        let mut value_bytes = Zeroizing::new(jcs_utf8_bytes(v)?);
        if value_bytes.len() > max_value_len {
            return Err(VcError::InvalidCredential);
        }

        let mut salt = generate_nonzero_salt(rng, salt_len)?;

        let path = format!("/claims/{}", name);

        let inner = claim_inner_digest(clm_tag, &value_bytes, &salt)?;
        let leaf = leaf_digest(leaf_tag, &path, &inner)?;

        leaf_hashes.push(leaf);

        let opening_index = u32::try_from(idx).map_err(|_| VcError::InvalidCredential)?;

        openings.push(ClaimOpening {
            claim_path: path,
            salt: core::mem::take(&mut *salt),
            value: core::mem::take(&mut *value_bytes),
            index: opening_index,
            merkle_path: Vec::new(), // filled after tree built
        });
    }

    // 3) Build Merkle tree (pad to next power-of-two)
    let MerkleBuild {
        root,
        depth,
        paths_by_index,
    } = build_merkle(leaf_hashes, node_tag)?;

    // Attach Merkle paths to openings (only for original claims, not padded dups)
    for (i, opening) in openings.iter_mut().enumerate() {
        let path = paths_by_index.get(i).ok_or(VcError::InvalidCredential)?;
        opening.merkle_path = path.iter().map(|h| h.to_vec()).collect();
    }

    let IssueInput {
        kind,
        profile_id,
        assurance,
        issuer_reference,
        issuer_verification_key,
        issuer_country,
        valid_from,
        valid_until,
        status,
        subject,
        claimset_id,
        domain_tags,
        limits,
        qeaa_compliance,
    } = input;

    // 4) Build public envelope (signature bytes populated after signing)
    let claims_commitment = ClaimsCommitment {
        merkle_root: root.to_vec(),
        claimset_id,
        hash_alg: "sha-256".to_string(),
        value_encoding: CLAIM_COMMITMENT_VALUE_ENCODING.to_owned(),
        domain_tags,
        limits,
    };

    let issuer_crypto_alg = signer.algorithm();
    let issuer_credential_alg = issuer_credential_algorithm(issuer_crypto_alg)?;
    if issuer_verification_key.alg != issuer_credential_alg {
        return Err(VcError::InvalidCredential);
    }
    let mut envelope = CredentialEnvelope {
        kind,
        profile_id,
        assurance,

        issuer_reference,
        issuer_country,

        valid_from,
        valid_until,

        status,
        subject: subject.clone(),
        claims_commitment,

        qeaa_compliance,

        // filled after signing
        issuer_signature: Signature {
            verification_key: issuer_verification_key.clone(),
            raw_rs: Vec::new(),
        },
    };

    // 5) Canonicalize + sign
    let signing_bytes =
        canonical_credential_bytes(&envelope).map_err(|_| VcError::Canonicalization)?;

    let envelope_hash = sha256(&signing_bytes);

    let sig_wire = signer.sign_payload(&signing_bytes)?;

    let sig_raw = normalize_signature_to_raw(issuer_crypto_alg, &sig_wire)?;

    envelope.issuer_signature.raw_rs = sig_raw.clone();

    // 6) Build subject-private bundle
    let holder_key = match &subject.holder_binding {
        HolderBinding::CryptographicKey(key) => Some(key.clone()),
        HolderBinding::ClaimsBased(_) | HolderBinding::BearerWithoutBinding => None,
    };
    let subject_bundle = SubjectPrivateBundle {
        holder_key,
        envelope_hash: envelope_hash.to_vec(),
        issuer_signature: Signature {
            verification_key: issuer_verification_key,
            raw_rs: sig_raw,
        },
        tree: MerkleTreeInfo {
            depth: u32::try_from(depth).map_err(|_| VcError::InvalidCredential)?,
            count: u32::try_from(names.len()).map_err(|_| VcError::InvalidCredential)?,
        },
        claims: openings,
    };

    let proof_binding = build_credential_proof_binding(&envelope, &subject_bundle, signer)?;

    Ok(IssueResult {
        envelope,
        subject_bundle,
        proof_binding,
    })
}

fn build_credential_proof_binding(
    envelope: &CredentialEnvelope,
    subject_bundle: &SubjectPrivateBundle,
    signer: &dyn CredentialPayloadSigner,
) -> Result<Option<CredentialProofBinding>, VcError> {
    if signer.algorithm() != CryptoAlg::P256 {
        return Ok(None);
    }

    let Some(holder_key) = subject_bundle.holder_key.as_ref() else {
        return Ok(None);
    };
    if envelope.issuer_signature.verification_key.alg != CredentialAlgorithm::P256
        || holder_key.alg != CredentialAlgorithm::P256
    {
        return Ok(None);
    }

    let (issuer_public_key_x, issuer_public_key_y) =
        p256_coordinates(&envelope.issuer_signature.verification_key.public_key)?;
    let (subject_public_key_x, subject_public_key_y) = p256_coordinates(&holder_key.public_key)?;
    let envelope_hash = <[u8; 32]>::try_from(subject_bundle.envelope_hash.as_slice())
        .map_err(|_| VcError::InvalidCredential)?;
    let claims_root = <[u8; 32]>::try_from(envelope.claims_commitment.merkle_root.as_slice())
        .map_err(|_| VcError::InvalidCredential)?;
    let issuer_envelope_signature =
        <[u8; 64]>::try_from(envelope.issuer_signature.raw_rs.as_slice())
            .map_err(|_| VcError::InvalidCredential)?;

    let root_payload = CredentialProofBinding::root_binding_payload(&envelope_hash, &claims_root)?;
    let issuer_root_binding_signature = normalize_signature_to_raw(
        CryptoAlg::P256,
        signer.sign_payload(root_payload.as_slice())?.as_slice(),
    )?;
    let subject_payload = CredentialProofBinding::subject_binding_payload(
        &envelope_hash,
        &subject_public_key_x,
        &subject_public_key_y,
    )?;
    let issuer_subject_binding_signature = normalize_signature_to_raw(
        CryptoAlg::P256,
        signer.sign_payload(subject_payload.as_slice())?.as_slice(),
    )?;
    let issuance_binding = CredentialProofBinding::issuance_binding(
        &envelope_hash,
        &claims_root,
        &issuer_public_key_x,
        &issuer_public_key_y,
        &subject_public_key_x,
        &subject_public_key_y,
    )?;

    Ok(Some(CredentialProofBinding {
        version: CREDENTIAL_PROOF_BINDING_VERSION,
        envelope_hash,
        claims_root,
        issuer_public_key_x,
        issuer_public_key_y,
        subject_public_key_x,
        subject_public_key_y,
        issuer_envelope_signature,
        issuer_root_binding_signature: issuer_root_binding_signature
            .as_slice()
            .try_into()
            .map_err(|_| VcError::InvalidCredential)?,
        issuer_subject_binding_signature: issuer_subject_binding_signature
            .as_slice()
            .try_into()
            .map_err(|_| VcError::InvalidCredential)?,
        issuance_binding,
    }))
}

// -----------------------------------------------------------------------------
// Helpers: signature format normalization
// -----------------------------------------------------------------------------

fn issuer_credential_algorithm(a: CryptoAlg) -> Result<CredentialAlgorithm, VcError> {
    match a {
        CryptoAlg::P256 => Ok(CredentialAlgorithm::P256),
        CryptoAlg::Secp256k1 => Ok(CredentialAlgorithm::Secp256k1),
        CryptoAlg::Ed25519 => Ok(CredentialAlgorithm::Ed25519),
        _ => Err(VcError::UnsupportedProfile),
    }
}

/// Normalize signature bytes to raw format for storage.
///
/// Rules:
/// - Ed25519: already raw
/// - P-256 ECDSA: accept DER or raw 64; store raw 64
/// - secp256k1 ECDSA: accept raw 64 or DER; store raw 64
fn normalize_signature_to_raw(alg: CryptoAlg, sig: &[u8]) -> Result<Vec<u8>, VcError> {
    match alg {
        CryptoAlg::Ed25519 => Ok(sig.to_vec()),

        CryptoAlg::P256 => {
            if sig.len() == 64 {
                return Ok(sig.to_vec());
            }
            p256_ecdsa_der_to_jose_signature(sig)
                .map(|signature| signature.to_vec())
                .map_err(|_| VcError::InvalidCredential)
        }

        CryptoAlg::Secp256k1 => {
            if sig.len() == 64 {
                return Ok(sig.to_vec());
            }
            secp256k1_ecdsa_der_to_jose_signature(sig)
                .map(|signature| signature.to_vec())
                .map_err(|_| VcError::InvalidCredential)
        }

        _ => Err(VcError::UnsupportedProfile),
    }
}

// -----------------------------------------------------------------------------
// Helpers: hashing + Merkle
// -----------------------------------------------------------------------------

fn sha256(data: &[u8]) -> [u8; 32] {
    sha2_256_digest(data).into_bytes()
}

fn claim_inner_digest(clm_tag: &[u8], value: &[u8], salt: &[u8]) -> Result<[u8; 32], VcError> {
    let value_len = u64::try_from(value.len()).map_err(|_| VcError::InvalidCredential)?;
    let encoded_len = value_len.to_be_bytes();
    sha256_parts(&[clm_tag, encoded_len.as_slice(), value, salt])
}

fn leaf_digest(leaf_tag: &[u8], claim_path: &str, inner: &[u8; 32]) -> Result<[u8; 32], VcError> {
    let name_hash = sha256(claim_path.as_bytes());
    sha256_parts(&[leaf_tag, name_hash.as_slice(), inner])
}

fn node_digest(node_tag: &[u8], left: &[u8; 32], right: &[u8; 32]) -> Result<[u8; 32], VcError> {
    sha256_parts(&[node_tag, left, right])
}

fn sha256_parts(parts: &[&[u8]]) -> Result<[u8; 32], VcError> {
    let capacity = parts.iter().try_fold(0_usize, |total, part| {
        total
            .checked_add(part.len())
            .ok_or(VcError::InvalidCredential)
    })?;
    let mut input = Zeroizing::new(Vec::with_capacity(capacity));
    for part in parts {
        input.extend_from_slice(part);
    }
    Ok(sha2_256_digest(&input).into_bytes())
}

type Hash32 = [u8; 32];

#[derive(Debug, Clone)]
struct MerkleBuild {
    root: Hash32,
    depth: usize,
    paths_by_index: Vec<Vec<Hash32>>,
}
