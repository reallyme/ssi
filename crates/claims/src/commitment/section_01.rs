// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::{
    claim_path, parse_claim_path, validate_claim_payload, validate_claim_value, ClaimValue,
    ClaimsError, ClaimsInvalidReason, ClaimsRegistry, MAX_CLAIMS_PER_REGISTRY,
    MAX_CLAIM_BYTES_VALUE_BYTES,
};
use reallyme_codec::base64url::bytes_to_base64url;
use reallyme_cose::{
    cose_key_from_slice, cose_key_signature_algorithm, cose_key_to_private_bytes,
    cose_key_to_public_bytes, CoseError, CoseSignatureAlgorithm,
};
use reallyme_crypto::sha2::digest as sha2_256_digest;
use std::collections::{BTreeMap, BTreeSet};
use reallyme_trust_x509::{
    certificate_subject_public_key_info, parse_subject_public_key_info_der,
    validate_certificate_der, SubjectPublicKeyAlgorithm,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Hash byte length for ReallyMe claim commitments using SHA-256.
pub const CLAIM_COMMITMENT_HASH_BYTES: usize = 32;

/// Supported hash algorithm label for claim commitments.
pub const CLAIM_COMMITMENT_HASH_ALG_SHA256: &str = "sha-256";

/// Supported canonical normalized claim value encoding.
pub const CLAIM_COMMITMENT_VALUE_ENCODING: &str = "RM-CV-JCS-V1";

/// Default maximum canonical claim value bytes committed by the builder.
pub const DEFAULT_COMMITMENT_MAX_VALUE_LEN: u32 = 4096;

/// Default per-claim salt length for new commitments.
pub const DEFAULT_COMMITMENT_SALT_LEN: u32 = 16;

/// Maximum claim openings accepted in one holder-private bundle.
pub const MAX_CLAIM_OPENINGS_PER_BUNDLE: usize = MAX_CLAIMS_PER_REGISTRY;

/// Maximum Merkle authentication path depth accepted for one opening.
pub const MAX_CLAIM_OPENING_MERKLE_DEPTH: usize = 64;

/// Maximum UTF-8 bytes for hash and encoding labels.
pub const MAX_COMMITMENT_LABEL_BYTES: usize = 32;

/// Maximum UTF-8 bytes for commitment domain separation tags.
pub const MAX_COMMITMENT_DOMAIN_TAG_BYTES: usize = 16;

/// Maximum bytes accepted for one public-key representation or certificate.
pub const MAX_PUBLIC_KEY_MATERIAL_BYTES: usize = 16 * 1024;

/// Maximum certificates accepted in one key-assurance chain.
pub const MAX_KEY_ASSURANCE_CERTIFICATES: usize = 16;

/// Public commitment to a credential's canonical claim set.
#[derive(Clone, Eq, PartialEq)]
pub struct ClaimsCommitment {
    /// Merkle root committing to all canonical claim openings.
    pub merkle_root: Vec<u8>,

    /// Credential claimset/profile identifier.
    pub claimset_id: String,

    /// Hash algorithm identifier.
    pub hash_alg: String,

    /// Encoding used before claim value commitment.
    pub value_encoding: String,

    /// Domain separation tags used by commitment hashing.
    pub domain_tags: DomainTags,

    /// Resource bounds used when creating openings.
    pub limits: CommitmentLimits,
}

/// Domain separation tags for claim commitment hashing.
#[derive(Clone, Eq, PartialEq)]
pub struct DomainTags {
    /// Inner claim-value domain tag.
    pub clm: String,

    /// Merkle leaf domain tag.
    pub leaf: String,

    /// Merkle internal-node domain tag.
    pub node: String,
}

/// Resource limits recorded in a claims commitment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommitmentLimits {
    /// Maximum canonical claim value length in bytes.
    pub max_value_len: u32,

    /// Salt length in bytes.
    pub salt_len: u32,
}

/// Holder-private claim opening bundle for one credential.
#[derive(Eq, PartialEq)]
pub struct SubjectPrivateBundle {
    /// Holder key for cryptographically bound credentials. Claims-based and
    /// bearer credentials deliberately carry no placeholder key.
    pub holder_key: Option<PublicKeyRef>,

    /// Hash of the public credential envelope canonical bytes.
    pub envelope_hash: Vec<u8>,

    /// Issuer signature copied from the public credential envelope.
    pub issuer_signature: Signature,

    /// Merkle tree metadata for the committed claims.
    pub tree: MerkleTreeInfo,

    /// Holder-private openings for individual claims.
    pub claims: Vec<ClaimOpening>,
}

/// Merkle tree metadata for committed claims.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MerkleTreeInfo {
    /// Tree depth.
    pub depth: u32,

    /// Number of original, unpadded claim leaves.
    pub count: u32,
}

/// Holder-private opening for one canonical claim.
#[derive(Eq, PartialEq)]
pub struct ClaimOpening {
    /// Canonical ReallyMe claim path such as `/claims/age`.
    pub claim_path: String,

    /// Per-claim salt used by the commitment.
    pub salt: Vec<u8>,

    /// Canonical encoded claim value bytes.
    pub value: Vec<u8>,

    /// Leaf index in the committed Merkle tree.
    pub index: u32,

    /// Sibling hashes from leaf to root.
    pub merkle_path: Vec<Vec<u8>>,
}

/// Credential key algorithm carried by the copied meproto credential shape.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialAlgorithm {
    /// Algorithm is absent.
    Unspecified,
    /// Ed25519 signature key.
    Ed25519,
    /// X25519 key agreement key.
    X25519,
    /// NIST P-256 key.
    P256,
    /// secp256k1 key.
    Secp256k1,
    /// secp256k1 signature with recovery id.
    Es256kRecovery,
    /// ML-DSA-65 signature key.
    MlDsa65,
    /// ML-DSA-87 signature key.
    MlDsa87,
    /// ML-KEM-768 KEM key.
    MlKem768,
    /// ML-KEM-1024 KEM key.
    MlKem1024,
    /// ML-DSA-44 signature key.
    MlDsa44,
}

/// Serialization applied to algorithm-specific raw public-key octets.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RawPublicKeySerialization {
    /// Fixed-width algorithm-specific bytes, such as an Ed25519 public key.
    FixedWidth,
    /// SEC1 compressed elliptic-curve point.
    Sec1Compressed,
    /// SEC1 uncompressed elliptic-curve point.
    Sec1Uncompressed,
}

/// One explicitly tagged public-key representation.
#[derive(Clone, Eq, PartialEq)]
pub enum PublicKeyRepresentation {
    /// RFC 7517 public JWK JSON bytes.
    JwkJson(Vec<u8>),
    /// RFC 9052 COSE_Key CBOR bytes.
    CoseKey(Vec<u8>),
    /// Multibase/multicodec Multikey bytes.
    Multikey(String),
    /// RFC 5280 SubjectPublicKeyInfo DER.
    SubjectPublicKeyInfoDer(Vec<u8>),
    /// Algorithm-specific bytes with explicit serialization.
    Raw {
        /// Serialization of `bytes`.
        serialization: RawPublicKeySerialization,
        /// Public-only key octets.
        bytes: Vec<u8>,
    },
}

/// Identifier or discovery mechanism for a verification key.
#[derive(Clone, Eq, PartialEq)]
pub enum KeyReference {
    /// DID URL selecting a verification method.
    DidVerificationMethod(String),
    /// Validated X.509 certificate encoded as DER.
    X509Certificate(Vec<u8>),
    /// The key is identified directly by its public representation.
    DirectPublicKey,
}

/// Evidence supporting a key, kept separate from identity and representation.
#[derive(Clone, Eq, PartialEq)]
pub enum KeyAssurance {
    /// No positive assurance evidence is asserted.
    None,
    /// Profile-defined key-attestation evidence.
    KeyAttestation(Vec<u8>),
    /// Profile-defined hardware-attestation evidence.
    HardwareAttestation(Vec<u8>),
    /// Validated X.509 certification path, leaf first.
    X509Chain(Vec<Vec<u8>>),
}

/// Public key reference used by credential and private-bundle records.
#[derive(Clone, Eq, PartialEq)]
pub struct PublicKeyRef {
    /// Key algorithm.
    pub alg: CredentialAlgorithm,
    /// Identifier or discovery mechanism.
    pub reference: KeyReference,
    /// Public material with an explicit representation tag.
    pub public_key: PublicKeyRepresentation,
    /// Evidence supporting this key.
    pub assurance: KeyAssurance,
}

/// Signature bytes plus verification method metadata.
#[derive(Eq, PartialEq)]
pub struct Signature {
    /// Public verification key, including independent reference,
    /// representation, and assurance axes.
    pub verification_key: PublicKeyRef,

    /// Raw signature bytes.
    pub raw_rs: Vec<u8>,
}

/// Source of per-claim commitment salts.
///
/// Issuer and wallet layers must inject an approved CSPRNG-backed source. The
/// claims crate only asks for opaque salt bytes so commitment construction does
/// not grow an undeclared randomness policy.
pub trait ClaimSaltSource {
    /// Fill the provided salt buffer for one canonical claim path.
    fn fill_salt(&mut self, claim_path: &str, salt: &mut [u8]) -> Result<(), ClaimsError>;
}

/// Inputs needed to build a public commitment and matching holder-private bundle.
pub struct ClaimCommitmentBuildInput<'a> {
    /// Registry that defines the committed claim set.
    pub registry: &'a ClaimsRegistry,

    /// Normalized credential claim payload.
    pub payload: &'a ClaimValue,

    /// Holder public key reference copied into the private bundle.
    pub holder_key: Option<PublicKeyRef>,

    /// Canonical public credential envelope hash.
    pub envelope_hash: Vec<u8>,

    /// Issuer signature copied into the private bundle.
    pub issuer_signature: Signature,

    /// Commitment resource bounds.
    pub limits: CommitmentLimits,

    /// Domain separation tags.
    pub domain_tags: DomainTags,
}

/// Constructed public commitment plus matching holder-private openings.
pub struct BuiltClaimsCommitment {
    /// Public commitment carried by the credential envelope.
    pub commitment: ClaimsCommitment,

    /// Holder-private bundle containing salts, values, and Merkle proofs.
    pub bundle: SubjectPrivateBundle,
}

impl core::fmt::Debug for ClaimsCommitment {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ClaimsCommitment")
            .field("merkle_root", &redacted_len(self.merkle_root.len()))
            .field("claimset_id", &self.claimset_id)
            .field("hash_alg", &self.hash_alg)
            .field("value_encoding", &self.value_encoding)
            .field("domain_tags", &self.domain_tags)
            .field("limits", &self.limits)
            .finish()
    }
}

impl core::fmt::Debug for DomainTags {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("DomainTags")
            .field("clm", &redacted_len(self.clm.len()))
            .field("leaf", &redacted_len(self.leaf.len()))
            .field("node", &redacted_len(self.node.len()))
            .finish()
    }
}

impl core::fmt::Debug for SubjectPrivateBundle {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("SubjectPrivateBundle")
            .field("holder_key", &self.holder_key)
            .field("envelope_hash", &redacted_len(self.envelope_hash.len()))
            .field("issuer_signature", &self.issuer_signature)
            .field("tree", &self.tree)
            .field("claims", &redacted_len(self.claims.len()))
            .finish()
    }
}

impl core::fmt::Debug for PublicKeyRef {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("PublicKeyRef")
            .field("alg", &self.alg)
            .field("reference", &self.reference)
            .field("public_key", &self.public_key)
            .field("assurance", &self.assurance)
            .finish()
    }
}

impl core::fmt::Debug for PublicKeyRepresentation {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let (kind, len) = match self {
            Self::JwkJson(value) => ("jwk_json", value.len()),
            Self::CoseKey(value) => ("cose_key", value.len()),
            Self::Multikey(value) => ("multikey", value.len()),
            Self::SubjectPublicKeyInfoDer(value) => ("spki_der", value.len()),
            Self::Raw { bytes, .. } => ("raw", bytes.len()),
        };
        formatter
            .debug_struct("PublicKeyRepresentation")
            .field("kind", &kind)
            .field("bytes", &redacted_len(len))
            .finish()
    }
}

impl core::fmt::Debug for KeyReference {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::DidVerificationMethod(value) => formatter
                .debug_tuple("DidVerificationMethod")
                .field(&redacted_len(value.len()))
                .finish(),
            Self::X509Certificate(value) => formatter
                .debug_tuple("X509Certificate")
                .field(&redacted_len(value.len()))
                .finish(),
            Self::DirectPublicKey => formatter.write_str("DirectPublicKey"),
        }
    }
}

impl core::fmt::Debug for KeyAssurance {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::None => formatter.write_str("None"),
            Self::KeyAttestation(value) => formatter
                .debug_tuple("KeyAttestation")
                .field(&redacted_len(value.len()))
                .finish(),
            Self::HardwareAttestation(value) => formatter
                .debug_tuple("HardwareAttestation")
                .field(&redacted_len(value.len()))
                .finish(),
            Self::X509Chain(value) => formatter
                .debug_tuple("X509Chain")
                .field(&redacted_len(value.len()))
                .finish(),
        }
    }
}

impl core::fmt::Debug for Signature {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("Signature")
            .field("verification_key", &self.verification_key)
            .field("raw_rs", &redacted_len(self.raw_rs.len()))
            .finish()
    }
}

impl core::fmt::Debug for ClaimOpening {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ClaimOpening")
            .field("claim_path", &self.claim_path)
            .field("salt", &redacted_len(self.salt.len()))
            .field("value", &redacted_len(self.value.len()))
            .field("index", &self.index)
            .field("merkle_path", &redacted_len(self.merkle_path.len()))
            .finish()
    }
}

impl Zeroize for ClaimsCommitment {
    fn zeroize(&mut self) {
        self.merkle_root.zeroize();
        self.claimset_id.zeroize();
        self.hash_alg.zeroize();
        self.value_encoding.zeroize();
        self.domain_tags.zeroize();
    }
}

impl Drop for ClaimsCommitment {
    fn drop(&mut self) {
        self.zeroize();
    }
}
