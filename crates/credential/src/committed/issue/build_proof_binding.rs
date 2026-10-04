// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

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
    let validity_status_payload = CredentialProofBinding::validity_status_binding_payload(
        envelope,
        &envelope_hash,
        &claims_root,
    )?;
    let issuer_validity_status_signature = normalize_signature_to_raw(
        CryptoAlg::P256,
        signer.sign_payload(validity_status_payload.as_slice())?.as_slice(),
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
        issuer_validity_status_signature: issuer_validity_status_signature
            .as_slice()
            .try_into()
            .map_err(|_| VcError::InvalidCredential)?,
        issuance_binding,
    }))
}
