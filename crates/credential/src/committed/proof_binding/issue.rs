// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

/// Sign the claim-root and subject-key bindings for an already signed SSI
/// credential envelope. The issuer must sign the same envelope that the
/// wallet will later use as its circuit witness.
pub fn issue_credential_proof_binding(
    envelope: &CredentialEnvelope,
    signer: &dyn CredentialIssuerSigner,
) -> Result<CredentialProofBinding, VcError> {
    crate::validate_credential_envelope(envelope).map_err(|_| VcError::InvalidCredential)?;
    if envelope.issuer_signature.verification_key.alg != CredentialAlgorithm::P256
        || signer.verification_key() != &envelope.issuer_signature.verification_key
    {
        return Err(VcError::ProofBindingTrustedIssuerMismatch);
    }
    let subject_key = match &envelope.subject.holder_binding {
        HolderBinding::CryptographicKey(key) if key.alg == CredentialAlgorithm::P256 => key,
        HolderBinding::CryptographicKey(_)
        | HolderBinding::ClaimsBased(_)
        | HolderBinding::BearerWithoutBinding => return Err(VcError::InvalidCredential),
    };
    let (issuer_public_key_x, issuer_public_key_y) =
        p256_coordinates(&envelope.issuer_signature.verification_key.public_key)?;
    let (subject_public_key_x, subject_public_key_y) = p256_coordinates(&subject_key.public_key)?;
    let signing_payload = Zeroizing::new(canonical_credential_bytes(envelope)?);
    let envelope_hash = sha2_256_digest(signing_payload.as_slice()).into_bytes();
    let claims_root = envelope
        .claims_commitment
        .merkle_root
        .as_slice()
        .try_into()
        .map_err(|_| VcError::InvalidCredential)?;
    let issuer_envelope_signature = envelope
        .issuer_signature
        .raw_rs
        .as_slice()
        .try_into()
        .map_err(|_| VcError::ProofBindingSignatureInvalid)?;
    let root_payload = Zeroizing::new(CredentialProofBinding::root_binding_payload(
        &envelope_hash,
        &claims_root,
    )?);
    let issuer_root_binding_signature =
        sign_p256_binding_payload(signer, root_payload.as_slice())?;
    let subject_payload = Zeroizing::new(CredentialProofBinding::subject_binding_payload(
        &envelope_hash,
        &subject_public_key_x,
        &subject_public_key_y,
    )?);
    let issuer_subject_binding_signature =
        sign_p256_binding_payload(signer, subject_payload.as_slice())?;
    let validity_status_payload =
        Zeroizing::new(CredentialProofBinding::validity_status_binding_payload(
            envelope,
            &envelope_hash,
            &claims_root,
        )?);
    let issuer_validity_status_signature =
        sign_p256_binding_payload(signer, validity_status_payload.as_slice())?;
    let issuance_binding = CredentialProofBinding::issuance_binding(
        &envelope_hash,
        &claims_root,
        &issuer_public_key_x,
        &issuer_public_key_y,
        &subject_public_key_x,
        &subject_public_key_y,
    )?;
    let binding = CredentialProofBinding {
        version: CREDENTIAL_PROOF_BINDING_VERSION,
        envelope_hash,
        claims_root,
        issuer_public_key_x,
        issuer_public_key_y,
        subject_public_key_x,
        subject_public_key_y,
        issuer_envelope_signature,
        issuer_root_binding_signature,
        issuer_subject_binding_signature,
        issuer_validity_status_signature,
        issuance_binding,
    };
    let mut issuer_public_key = [0_u8; P256_SEC1_UNCOMPRESSED_BYTES];
    issuer_public_key[0] = P256_SEC1_UNCOMPRESSED_PREFIX;
    issuer_public_key[P256_X_START..P256_X_END].copy_from_slice(&issuer_public_key_x);
    issuer_public_key[P256_X_END..P256_Y_END].copy_from_slice(&issuer_public_key_y);
    for (payload, signature) in [
        (
            signing_payload.as_slice(),
            binding.issuer_envelope_signature,
        ),
        (
            root_payload.as_slice(),
            binding.issuer_root_binding_signature,
        ),
        (
            subject_payload.as_slice(),
            binding.issuer_subject_binding_signature,
        ),
        (
            validity_status_payload.as_slice(),
            binding.issuer_validity_status_signature,
        ),
    ] {
        let der = p256_ecdsa_jose_signature_to_der(&signature)
            .map_err(|_| VcError::ProofBindingSignatureInvalid)?;
        verify_signature(
            CryptoAlgorithm::P256,
            &issuer_public_key,
            payload,
            der.as_slice(),
        )
        .map_err(|_| VcError::ProofBindingSignatureInvalid)?;
    }
    Ok(binding)
}

fn sign_p256_binding_payload(
    signer: &dyn CredentialIssuerSigner,
    payload: &[u8],
) -> Result<[u8; 64], VcError> {
    // Keystores may return either JOSE raw P-256 bytes or DER. Store one
    // canonical representation and verify it against the declared issuer key.
    let signature = Zeroizing::new(
        signer
            .sign_credential_payload(payload)
            .map_err(|_| VcError::ProofBindingSignatureInvalid)?,
    );
    if signature.len() == 64 {
        return signature
            .as_slice()
            .try_into()
            .map_err(|_| VcError::ProofBindingSignatureInvalid);
    }
    p256_ecdsa_der_to_jose_signature(signature.as_slice())
        .map_err(|_| VcError::ProofBindingSignatureInvalid)
}
