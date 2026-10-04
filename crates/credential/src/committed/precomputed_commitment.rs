// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Signs an issuer-approved claim commitment without rebuilding SSI's general
//! claim tree. The authority that approves the root must verify the selected
//! claim transcript before calling this operation.

use reallyme_credential_claims::{ClaimsCommitment, CredentialAlgorithm, Signature};
use reallyme_crypto::p256::p256_ecdsa_der_to_jose_signature;
use zeroize::Zeroizing;

use crate::committed::{
    error::VcError,
    issue::IssueInput,
    model::{CredentialEnvelope, HolderBinding},
    proof_binding::{issue_credential_proof_binding, CredentialProofBinding},
};
use crate::{
    sign_credential_envelope, validate_credential_unsigned_envelope, CredentialError,
    CredentialIssuerSigner, CredentialSignatureReason,
};

const CLAIM_ROOT_BYTES: usize = 32;
const P256_SIGNATURE_BYTES: usize = 64;

/// The signed public envelope and its matching issuer-signed proof transcript.
///
/// Holder-private claim openings stay with the commitment owner; this result
/// deliberately does not fabricate a general SSI claim-opening bundle.
pub struct PrecomputedCommitmentIssueResult {
    /// Public credential whose signature covers the exact approved root.
    pub envelope: CredentialEnvelope,
    /// Signatures binding that root to the issuer, holder, validity, and status.
    pub proof_binding: CredentialProofBinding,
}

/// Issue a credential after the issuer has independently approved a commitment.
///
/// The caller is responsible for recomputing the selected commitment from
/// authoritative claims and the holder's opaque leaf before passing it here.
/// This operation owns the signing sequence so no caller needs to replace a
/// claim root in an already signed credential and then re-sign it.
pub fn issue_credential_with_precomputed_commitment(
    input: IssueInput,
    commitment: ClaimsCommitment,
    signer: &dyn CredentialIssuerSigner,
) -> Result<PrecomputedCommitmentIssueResult, VcError> {
    if commitment.merkle_root.len() != CLAIM_ROOT_BYTES
        || commitment.merkle_root.iter().all(|byte| *byte == 0)
        || commitment.claimset_id != input.claimset_id
        || commitment.domain_tags != input.domain_tags
        || commitment.limits != input.limits
        || input.issuer_verification_key.alg != CredentialAlgorithm::P256
        || signer.verification_key() != &input.issuer_verification_key
        || !matches!(
            input.subject.holder_binding,
            HolderBinding::CryptographicKey(ref key) if key.alg == CredentialAlgorithm::P256
        )
    {
        return Err(VcError::InvalidCredential);
    }

    let mut envelope = CredentialEnvelope {
        kind: input.kind,
        profile_id: input.profile_id,
        assurance: input.assurance,
        issuer_reference: input.issuer_reference,
        issuer_country: input.issuer_country,
        valid_from: input.valid_from,
        valid_until: input.valid_until,
        status: input.status,
        subject: input.subject,
        claims_commitment: commitment,
        qeaa_compliance: input.qeaa_compliance,
        issuer_signature: Signature {
            verification_key: input.issuer_verification_key,
            raw_rs: Vec::new(),
        },
    };
    validate_credential_unsigned_envelope(&envelope).map_err(|_| VcError::InvalidCredential)?;

    let normalized_signer = RawP256Signer { signer };
    sign_credential_envelope(&mut envelope, &normalized_signer)
        .map_err(|_| VcError::ProofBindingSignatureInvalid)?;
    let proof_binding = issue_credential_proof_binding(&envelope, &normalized_signer)?;

    Ok(PrecomputedCommitmentIssueResult {
        envelope,
        proof_binding,
    })
}

/// SSI's generic signing boundary permits DER or raw ECDSA output. The proof
/// transcript has one fixed raw-signature encoding, so normalize at this edge.
struct RawP256Signer<'a> {
    signer: &'a dyn CredentialIssuerSigner,
}

impl CredentialIssuerSigner for RawP256Signer<'_> {
    fn verification_key(&self) -> &reallyme_credential_claims::PublicKeyRef {
        self.signer.verification_key()
    }

    fn sign_credential_payload(&self, payload: &[u8]) -> Result<Vec<u8>, CredentialError> {
        let signature = Zeroizing::new(self.signer.sign_credential_payload(payload)?);
        if signature.len() == P256_SIGNATURE_BYTES {
            return Ok(signature.to_vec());
        }
        p256_ecdsa_der_to_jose_signature(signature.as_slice())
            .map(|raw| raw.to_vec())
            .map_err(|_| CredentialError::Signature(CredentialSignatureReason::SigningFailed))
    }
}
