// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::{
    credential_signing_payload, validate_credential_envelope,
    validate_credential_unsigned_envelope, CredentialEnvelope, CredentialError,
    CredentialSignatureReason, PartyReference,
};
use reallyme_credential_claims::{CredentialAlgorithm, PublicKeyRef, Signature};
use reallyme_crypto::{core::Algorithm, dispatch};

/// Issuer signer for a credential's canonical signing payload.
pub trait CredentialIssuerSigner {
    /// Public verification key and its reference, representation, and assurance.
    fn verification_key(&self) -> &PublicKeyRef;

    /// Sign the canonical credential payload.
    fn sign_credential_payload(&self, payload: &[u8]) -> Result<Vec<u8>, CredentialError>;
}

/// Issuer verifier for a credential's canonical signing payload.
pub trait CredentialIssuerVerifier {
    /// Verify an issuer signature over the canonical credential payload.
    fn verify_credential_payload(
        &self,
        issuer_reference: &PartyReference,
        verification_key: &PublicKeyRef,
        payload: &[u8],
        signature: &[u8],
    ) -> Result<(), CredentialError>;
}

/// Produce and attach an issuer signature for a credential envelope.
pub fn sign_credential_envelope(
    envelope: &mut CredentialEnvelope,
    signer: &dyn CredentialIssuerSigner,
) -> Result<(), CredentialError> {
    validate_credential_unsigned_envelope(envelope)?;
    let payload = credential_signing_payload(envelope)?;
    let raw_rs = signer.sign_credential_payload(payload.as_slice())?;
    envelope.issuer_signature = Signature {
        verification_key: signer.verification_key().clone(),
        raw_rs,
    };
    validate_credential_envelope(envelope)
}

/// Verify the issuer signature over the credential's canonical payload.
pub fn verify_credential_issuer_signature(
    envelope: &CredentialEnvelope,
    verifier: &dyn CredentialIssuerVerifier,
) -> Result<(), CredentialError> {
    validate_credential_envelope(envelope)?;
    let payload = credential_signing_payload(envelope)?;
    verifier.verify_credential_payload(
        &envelope.issuer_reference,
        &envelope.issuer_signature.verification_key,
        payload.as_slice(),
        envelope.issuer_signature.raw_rs.as_slice(),
    )
}

/// Dispatch-backed issuer signer using ReallyMe Crypto.
pub struct DispatchCredentialIssuerSigner<'a> {
    /// Issuer private key bytes accepted by the selected ReallyMe Crypto lane.
    pub private_key: &'a [u8],

    /// Public verification key stored with the signature.
    pub verification_key: &'a PublicKeyRef,
}

impl CredentialIssuerSigner for DispatchCredentialIssuerSigner<'_> {
    fn verification_key(&self) -> &PublicKeyRef {
        self.verification_key
    }

    fn sign_credential_payload(&self, payload: &[u8]) -> Result<Vec<u8>, CredentialError> {
        let algorithm = credential_algorithm_to_crypto_algorithm(self.verification_key.alg)?;
        dispatch::sign(algorithm, self.private_key, payload)
            .map_err(|_| CredentialError::Signature(CredentialSignatureReason::SigningFailed))
    }
}

/// Dispatch-backed issuer verifier using ReallyMe Crypto.
pub struct DispatchCredentialIssuerVerifier<'a> {
    /// Issuer public key bytes accepted by the selected ReallyMe Crypto lane.
    pub public_key: &'a [u8],

    /// Expected key metadata for the supplied public key bytes.
    pub expected_verification_key: &'a PublicKeyRef,
}

impl CredentialIssuerVerifier for DispatchCredentialIssuerVerifier<'_> {
    fn verify_credential_payload(
        &self,
        _issuer_reference: &PartyReference,
        verification_key: &PublicKeyRef,
        payload: &[u8],
        signature: &[u8],
    ) -> Result<(), CredentialError> {
        if self.expected_verification_key != verification_key {
            return Err(CredentialError::Signature(
                CredentialSignatureReason::VerificationMethodMismatch,
            ));
        }
        let algorithm = credential_algorithm_to_crypto_algorithm(verification_key.alg)?;
        dispatch::verify(algorithm, self.public_key, payload, signature)
            .map_err(|_| CredentialError::Signature(CredentialSignatureReason::VerificationFailed))
    }
}

fn credential_algorithm_to_crypto_algorithm(
    algorithm: CredentialAlgorithm,
) -> Result<Algorithm, CredentialError> {
    match algorithm {
        CredentialAlgorithm::Ed25519 => Ok(Algorithm::Ed25519),
        CredentialAlgorithm::P256 => Ok(Algorithm::P256),
        CredentialAlgorithm::Secp256k1 => Ok(Algorithm::Secp256k1),
        CredentialAlgorithm::MlDsa44 => Ok(Algorithm::MlDsa44),
        CredentialAlgorithm::MlDsa65 => Ok(Algorithm::MlDsa65),
        CredentialAlgorithm::MlDsa87 => Ok(Algorithm::MlDsa87),
        CredentialAlgorithm::Unspecified
        | CredentialAlgorithm::X25519
        | CredentialAlgorithm::Es256kRecovery
        | CredentialAlgorithm::MlKem768
        | CredentialAlgorithm::MlKem1024 => Err(CredentialError::Signature(
            CredentialSignatureReason::UnsupportedAlgorithm,
        )),
    }
}
