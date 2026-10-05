// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Versioned credential material used by privacy-preserving proof adapters.
//!
//! The type is owned by SSI because it describes one issued credential. It
//! does not select a proof system, circuit, provider, or presentation format.

use reallyme_crypto::{
    p256::{
        decompress_public_key, p256_ecdsa_der_to_jose_signature, p256_ecdsa_jose_signature_to_der,
    },
    sha2::digest as sha2_256_digest,
};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crypto_core::Algorithm as CryptoAlgorithm;
use crypto_dispatch::verify as verify_signature;

use crate::committed::{
    canonical::canonical_credential_bytes,
    error::VcError,
    model::{
        CredentialAlgorithm, CredentialEnvelope, HolderBinding, PublicKeyRepresentation,
        RawPublicKeySerialization, SubjectPrivateBundle,
    },
};
use crate::CredentialIssuerSigner;
use reallyme_credential_status::StatusPurpose;

const ENVELOPE_BINDING_TAG: &[u8] = b"ENVB1";
const CREDENTIAL_BINDING_TAG: &[u8] = b"CREDB1";
const ROOT_BINDING_TAG: &[u8] = b"BINDMRK1";
const SUBJECT_BINDING_TAG: &[u8] = b"BINDSUB1";
const VALIDITY_STATUS_BINDING_TAG: &[u8] = b"BINDVLD1";
const ISSUANCE_BINDING_TAG: &[u8] = b"RMCPB1";
const P256_SEC1_UNCOMPRESSED_BYTES: usize = 65;
const P256_SEC1_UNCOMPRESSED_PREFIX: u8 = 0x04;
const P256_X_START: usize = 1;
const P256_X_END: usize = 33;
const P256_Y_END: usize = 65;

/// Current version of the SSI credential-proof binding contract.
pub const CREDENTIAL_PROOF_BINDING_VERSION: u32 = 1;

/// Issuer-authenticated material linking a credential envelope, claim root,
/// and holder key for privacy-preserving proof construction.
///
/// This material is public but correlatable. Debug output is deliberately
/// redacted and owned bytes are zeroized on drop.
#[derive(Clone, Eq, PartialEq)]
pub struct CredentialProofBinding {
    /// Version of this binding contract.
    pub version: u32,
    /// SHA-256 of the canonical issuer signing payload.
    pub envelope_hash: [u8; 32],
    /// Merkle root committed by the credential envelope.
    pub claims_root: [u8; 32],
    /// P-256 issuer public-key x coordinate.
    pub issuer_public_key_x: [u8; 32],
    /// P-256 issuer public-key y coordinate.
    pub issuer_public_key_y: [u8; 32],
    /// P-256 holder public-key x coordinate.
    pub subject_public_key_x: [u8; 32],
    /// P-256 holder public-key y coordinate.
    pub subject_public_key_y: [u8; 32],
    /// Issuer signature authenticating the canonical credential envelope.
    pub issuer_envelope_signature: [u8; 64],
    /// Issuer signature authenticating the envelope-to-claim-root link.
    pub issuer_root_binding_signature: [u8; 64],
    /// Issuer signature authenticating the envelope-to-holder-key link.
    pub issuer_subject_binding_signature: [u8; 64],
    /// Issuer signature over the exact envelope's dates and status pointer.
    /// The common-root verifier proves this transcript without revealing the
    /// holder-specific status index or original subject identifier.
    pub issuer_validity_status_signature: [u8; 64],
    /// Stable commitment identifying this exact issuance and holder binding.
    pub issuance_binding: [u8; 32],
}

impl CredentialProofBinding {
    /// Computes the session-scoped envelope commitment expected by the v1
    /// credential-envelope and credential-root proof stages.
    pub fn envelope_binding(
        &self,
        challenge: [u8; 32],
        audience_hash: [u8; 32],
        expiry_unix: u64,
    ) -> Result<[u8; 32], VcError> {
        hash_parts(&[
            ENVELOPE_BINDING_TAG,
            &self.issuer_public_key_x,
            &self.issuer_public_key_y,
            &self.envelope_hash,
            &challenge,
            &audience_hash,
            &expiry_unix.to_be_bytes(),
        ])
    }

    /// Computes the session-scoped credential commitment expected by the v1
    /// common-root lineage, claim, and issuer-status proof stages.
    ///
    /// The transaction-data hash is part of the circuit's `CREDB1` transcript.
    /// Omitting it would make this issuer helper disagree with the proof inputs
    /// for requests that carry transaction data.
    pub fn credential_binding(
        &self,
        challenge: [u8; 32],
        audience_hash: [u8; 32],
        transaction_data_hash: [u8; 32],
        expiry_unix: u64,
    ) -> Result<[u8; 32], VcError> {
        hash_parts(&[
            CREDENTIAL_BINDING_TAG,
            &self.issuer_public_key_x,
            &self.issuer_public_key_y,
            &self.envelope_hash,
            &self.claims_root,
            &challenge,
            &audience_hash,
            &transaction_data_hash,
            &expiry_unix.to_be_bytes(),
        ])
    }

    pub(crate) fn root_binding_payload(
        envelope_hash: &[u8; 32],
        claims_root: &[u8; 32],
    ) -> Result<Vec<u8>, VcError> {
        concatenate_parts(&[ROOT_BINDING_TAG, envelope_hash, claims_root])
    }

    pub(crate) fn subject_binding_payload(
        envelope_hash: &[u8; 32],
        subject_public_key_x: &[u8; 32],
        subject_public_key_y: &[u8; 32],
    ) -> Result<Vec<u8>, VcError> {
        concatenate_parts(&[
            SUBJECT_BINDING_TAG,
            envelope_hash,
            subject_public_key_x,
            subject_public_key_y,
        ])
    }

    /// Fixed-width issuer transcript used by the private credential-validity
    /// and current-status proof. These values must come from the same signed
    /// envelope identified by `envelope_hash`.
    pub fn validity_status_binding_payload(
        envelope: &CredentialEnvelope,
        envelope_hash: &[u8; 32],
        claims_root: &[u8; 32],
    ) -> Result<Vec<u8>, VcError> {
        let valid_from =
            u64::try_from(envelope.valid_from).map_err(|_| VcError::InvalidCredential)?;
        let valid_until =
            u64::try_from(envelope.valid_until).map_err(|_| VcError::InvalidCredential)?;
        if valid_from >= valid_until {
            return Err(VcError::InvalidCredential);
        }
        let purpose = match envelope.status.purpose {
            StatusPurpose::Revocation => 1_u8,
            StatusPurpose::Suspension => 2_u8,
            _ => return Err(VcError::InvalidCredential),
        };
        let url_hash = sha2_256_digest(envelope.status.status_list_url.as_bytes()).into_bytes();
        concatenate_parts(&[
            VALIDITY_STATUS_BINDING_TAG,
            envelope_hash,
            claims_root,
            &valid_from.to_be_bytes(),
            &valid_until.to_be_bytes(),
            &url_hash,
            &envelope.status.status_list_id,
            &envelope.status.status_list_index.to_be_bytes(),
            &[purpose],
        ])
    }

    pub(crate) fn issuance_binding(
        envelope_hash: &[u8; 32],
        claims_root: &[u8; 32],
        issuer_public_key_x: &[u8; 32],
        issuer_public_key_y: &[u8; 32],
        subject_public_key_x: &[u8; 32],
        subject_public_key_y: &[u8; 32],
    ) -> Result<[u8; 32], VcError> {
        hash_parts(&[
            ISSUANCE_BINDING_TAG,
            &CREDENTIAL_PROOF_BINDING_VERSION.to_be_bytes(),
            envelope_hash,
            claims_root,
            issuer_public_key_x,
            issuer_public_key_y,
            subject_public_key_x,
            subject_public_key_y,
        ])
    }
}

include!("proof_binding/issue.rs");

/// Validates that proof material belongs to the exact public envelope and
/// holder-private bundle with which it is stored and was authenticated by the
/// issuer key supplied by the caller's trust resolution.
///
/// All four issuer signatures are verified. A binding copied from another
/// credential, issuer, holder, or issuance fails before witness construction.
/// The embedded verification key is credential data and is never treated as a
/// trust anchor.
pub fn validate_credential_proof_binding(
    envelope: &CredentialEnvelope,
    subject_bundle: &SubjectPrivateBundle,
    binding: &CredentialProofBinding,
    trusted_issuer_public_key: &[u8],
) -> Result<(), VcError> {
    crate::validate_credential_with_bundle(envelope, subject_bundle)
        .map_err(|_| VcError::InvalidCredential)?;
    validate_credential_proof_binding_public(envelope, binding, trusted_issuer_public_key)
}

/// Validates the public issuer-signed binding without assuming an SSI claim tree.
///
/// External commitment profiles have their own private openings and transcript
/// rules. Their profile owner must separately verify the root against approved
/// claims; this operation authenticates the exact envelope, root, holder key,
/// validity interval, and status pointer using a trusted issuer key.
pub fn validate_credential_proof_binding_public(
    envelope: &CredentialEnvelope,
    binding: &CredentialProofBinding,
    trusted_issuer_public_key: &[u8],
) -> Result<(), VcError> {
    crate::validate_credential_envelope(envelope).map_err(|_| VcError::InvalidCredential)?;
    if binding.version != CREDENTIAL_PROOF_BINDING_VERSION
        || envelope.issuer_signature.verification_key.alg != CredentialAlgorithm::P256
        || binding.issuer_envelope_signature.as_slice()
            != envelope.issuer_signature.raw_rs.as_slice()
    {
        return Err(VcError::ProofBindingMismatch);
    }

    let envelope_hash =
        sha2_256_digest(canonical_credential_bytes(envelope)?.as_slice()).into_bytes();
    let claims_root = <[u8; 32]>::try_from(envelope.claims_commitment.merkle_root.as_slice())
        .map_err(|_| VcError::InvalidCredential)?;
    let (issuer_public_key_x, issuer_public_key_y) =
        p256_coordinates(&envelope.issuer_signature.verification_key.public_key)?;
    let (trusted_issuer_public_key_x, trusted_issuer_public_key_y) =
        p256_raw_coordinates(trusted_issuer_public_key)?;
    if !reallyme_crypto::operations::constant_time::equal_fixed(
        &issuer_public_key_x,
        &trusted_issuer_public_key_x,
    ) || !reallyme_crypto::operations::constant_time::equal_fixed(
        &issuer_public_key_y,
        &trusted_issuer_public_key_y,
    ) {
        return Err(VcError::ProofBindingTrustedIssuerMismatch);
    }
    let subject_key = match &envelope.subject.holder_binding {
        HolderBinding::CryptographicKey(key) if key.alg == CredentialAlgorithm::P256 => key,
        HolderBinding::CryptographicKey(_)
        | HolderBinding::ClaimsBased(_)
        | HolderBinding::BearerWithoutBinding => return Err(VcError::InvalidCredential),
    };
    let (subject_public_key_x, subject_public_key_y) = p256_coordinates(&subject_key.public_key)?;
    let issuance_binding = CredentialProofBinding::issuance_binding(
        &envelope_hash,
        &claims_root,
        &issuer_public_key_x,
        &issuer_public_key_y,
        &subject_public_key_x,
        &subject_public_key_y,
    )?;

    if binding.envelope_hash != envelope_hash
        || binding.claims_root != claims_root
        || binding.issuer_public_key_x != issuer_public_key_x
        || binding.issuer_public_key_y != issuer_public_key_y
        || binding.subject_public_key_x != subject_public_key_x
        || binding.subject_public_key_y != subject_public_key_y
        || binding.issuance_binding != issuance_binding
    {
        return Err(VcError::ProofBindingMismatch);
    }

    let envelope_signature = p256_ecdsa_jose_signature_to_der(&binding.issuer_envelope_signature)
        .map_err(|_| VcError::ProofBindingSignatureInvalid)?;
    verify_signature(
        CryptoAlgorithm::P256,
        trusted_issuer_public_key,
        canonical_credential_bytes(envelope)?.as_slice(),
        envelope_signature.as_slice(),
    )
    .map_err(|_| VcError::ProofBindingSignatureInvalid)?;
    let root_payload = CredentialProofBinding::root_binding_payload(&envelope_hash, &claims_root)?;
    let root_signature = p256_ecdsa_jose_signature_to_der(&binding.issuer_root_binding_signature)
        .map_err(|_| VcError::ProofBindingSignatureInvalid)?;
    verify_signature(
        CryptoAlgorithm::P256,
        trusted_issuer_public_key,
        root_payload.as_slice(),
        root_signature.as_slice(),
    )
    .map_err(|_| VcError::ProofBindingSignatureInvalid)?;
    let subject_payload = CredentialProofBinding::subject_binding_payload(
        &envelope_hash,
        &subject_public_key_x,
        &subject_public_key_y,
    )?;
    let subject_signature =
        p256_ecdsa_jose_signature_to_der(&binding.issuer_subject_binding_signature)
            .map_err(|_| VcError::ProofBindingSignatureInvalid)?;
    verify_signature(
        CryptoAlgorithm::P256,
        trusted_issuer_public_key,
        subject_payload.as_slice(),
        subject_signature.as_slice(),
    )
    .map_err(|_| VcError::ProofBindingSignatureInvalid)?;
    let validity_status_payload = CredentialProofBinding::validity_status_binding_payload(
        envelope,
        &envelope_hash,
        &claims_root,
    )?;
    let validity_status_signature =
        p256_ecdsa_jose_signature_to_der(&binding.issuer_validity_status_signature)
            .map_err(|_| VcError::ProofBindingSignatureInvalid)?;
    verify_signature(
        CryptoAlgorithm::P256,
        trusted_issuer_public_key,
        validity_status_payload.as_slice(),
        validity_status_signature.as_slice(),
    )
    .map_err(|_| VcError::ProofBindingSignatureInvalid)
}

impl core::fmt::Debug for CredentialProofBinding {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("CredentialProofBinding")
            .field("version", &self.version)
            .field("material", &"<redacted>")
            .finish()
    }
}

impl Zeroize for CredentialProofBinding {
    fn zeroize(&mut self) {
        self.version.zeroize();
        self.envelope_hash.zeroize();
        self.claims_root.zeroize();
        self.issuer_public_key_x.zeroize();
        self.issuer_public_key_y.zeroize();
        self.subject_public_key_x.zeroize();
        self.subject_public_key_y.zeroize();
        self.issuer_envelope_signature.zeroize();
        self.issuer_root_binding_signature.zeroize();
        self.issuer_subject_binding_signature.zeroize();
        self.issuer_validity_status_signature.zeroize();
        self.issuance_binding.zeroize();
    }
}

impl Drop for CredentialProofBinding {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for CredentialProofBinding {}

fn hash_parts(parts: &[&[u8]]) -> Result<[u8; 32], VcError> {
    let bytes = Zeroizing::new(concatenate_parts(parts)?);
    Ok(sha2_256_digest(bytes.as_slice()).into_bytes())
}

fn concatenate_parts(parts: &[&[u8]]) -> Result<Vec<u8>, VcError> {
    let capacity = parts.iter().try_fold(0_usize, |total, part| {
        total
            .checked_add(part.len())
            .ok_or(VcError::InvalidCredential)
    })?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(capacity)
        .map_err(|_| VcError::InvalidCredential)?;
    for part in parts {
        bytes.extend_from_slice(part);
    }
    Ok(bytes)
}

pub(crate) fn p256_coordinates(
    public_key: &PublicKeyRepresentation,
) -> Result<([u8; 32], [u8; 32]), VcError> {
    let PublicKeyRepresentation::Raw {
        serialization,
        bytes,
    } = public_key
    else {
        return Err(VcError::InvalidCredential);
    };

    match serialization {
        RawPublicKeySerialization::Sec1Compressed
            if bytes.len() == 33 && matches!(bytes.first(), Some(0x02 | 0x03)) =>
        {
            p256_raw_coordinates(bytes)
        }
        RawPublicKeySerialization::Sec1Uncompressed
            if bytes.len() == 65 && bytes.first() == Some(&0x04) =>
        {
            p256_raw_coordinates(bytes)
        }
        RawPublicKeySerialization::Sec1Compressed | RawPublicKeySerialization::Sec1Uncompressed => {
            Err(VcError::InvalidCredential)
        }
        RawPublicKeySerialization::FixedWidth => Err(VcError::InvalidCredential),
        _ => Err(VcError::InvalidCredential),
    }
}

#[cfg(test)]
#[path = "proof_binding_tests.rs"]
mod tests;

fn p256_raw_coordinates(public_key: &[u8]) -> Result<([u8; 32], [u8; 32]), VcError> {
    let uncompressed = match public_key.len() {
        33 => decompress_public_key(public_key).map_err(|_| VcError::InvalidCredential)?,
        65 => {
            let y_last = public_key
                .last()
                .copied()
                .ok_or(VcError::InvalidCredential)?;
            let mut compressed = [0_u8; 33];
            compressed[0] = if y_last & 1 == 0 { 0x02 } else { 0x03 };
            compressed
                .get_mut(1..)
                .ok_or(VcError::InvalidCredential)?
                .copy_from_slice(public_key.get(1..33).ok_or(VcError::InvalidCredential)?);
            let validated =
                decompress_public_key(&compressed).map_err(|_| VcError::InvalidCredential)?;
            if validated.as_slice() != public_key {
                return Err(VcError::InvalidCredential);
            }
            validated
        }
        _ => return Err(VcError::InvalidCredential),
    };
    if uncompressed.len() != 65 || uncompressed.first().copied() != Some(0x04) {
        return Err(VcError::InvalidCredential);
    }
    let x = uncompressed
        .get(1..33)
        .ok_or(VcError::InvalidCredential)?
        .try_into()
        .map_err(|_| VcError::InvalidCredential)?;
    let y = uncompressed
        .get(33..65)
        .ok_or(VcError::InvalidCredential)?
        .try_into()
        .map_err(|_| VcError::InvalidCredential)?;
    Ok((x, y))
}
