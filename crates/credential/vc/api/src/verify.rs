// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0
use crypto_core::Algorithm as CryptoAlg;
use identity_core_primitives::Algorithm as IdentityAlgorithm;

use reallyme_credential::committed::{
    model::{CredentialEnvelope, SubjectPrivateBundle},
    verify::{verify_credential as core_verify_credential, verify_merkle_only, VerifyResult},
};

use crate::error::VcApiError;

fn map_identity_to_crypto_alg(alg: IdentityAlgorithm) -> Result<CryptoAlg, VcApiError> {
    match alg {
        IdentityAlgorithm::Ed25519 => Ok(CryptoAlg::Ed25519),
        IdentityAlgorithm::P256 => Ok(CryptoAlg::P256),
        IdentityAlgorithm::Secp256k1 => Ok(CryptoAlg::Secp256k1),
        _ => Err(VcApiError::InvalidIssuer),
    }
}

/// ------------------------------------------------------------
/// Verify full credential (signature + Merkle if bundle provided)
/// ------------------------------------------------------------
pub fn validate_credential(
    envelope: &CredentialEnvelope,
    issuer_alg: CryptoAlg,
    issuer_public_key: &[u8],
    subject_bundle: Option<&SubjectPrivateBundle>,
) -> Result<VerifyResult, VcApiError> {
    core_verify_credential(envelope, issuer_alg, issuer_public_key, subject_bundle)
        .map_err(VcApiError::from)
}

/// Verify full credential (signature + Merkle if bundle provided), using a semantic algorithm.
pub fn validate_credential_with_identity_algorithm(
    envelope: &CredentialEnvelope,
    issuer_alg: IdentityAlgorithm,
    issuer_public_key: &[u8],
    subject_bundle: Option<&SubjectPrivateBundle>,
) -> Result<VerifyResult, VcApiError> {
    let crypto_alg = map_identity_to_crypto_alg(issuer_alg)?;
    validate_credential(envelope, crypto_alg, issuer_public_key, subject_bundle)
}

/// ------------------------------------------------------------
/// Verify issuer signature ONLY
/// ------------------------------------------------------------
pub fn verify_credential_signature(
    envelope: &CredentialEnvelope,
    issuer_alg: CryptoAlg,
    issuer_public_key: &[u8],
) -> Result<(), VcApiError> {
    core_verify_credential(envelope, issuer_alg, issuer_public_key, None)
        .map(|_| ())
        .map_err(VcApiError::from)
}

/// Verify issuer signature ONLY, using a semantic algorithm.
pub fn verify_credential_signature_with_identity_algorithm(
    envelope: &CredentialEnvelope,
    issuer_alg: IdentityAlgorithm,
    issuer_public_key: &[u8],
) -> Result<(), VcApiError> {
    let crypto_alg = map_identity_to_crypto_alg(issuer_alg)?;
    verify_credential_signature(envelope, crypto_alg, issuer_public_key)
}

/// ------------------------------------------------------------
/// Verify Merkle root ONLY (no signature verification)
/// ------------------------------------------------------------
pub fn verify_credential_merkle_root(
    envelope: &CredentialEnvelope,
    subject_bundle: &SubjectPrivateBundle,
) -> Result<(), VcApiError> {
    verify_merkle_only(envelope, subject_bundle).map_err(VcApiError::from)
}
