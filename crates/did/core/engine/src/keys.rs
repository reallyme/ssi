// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use identity_core_primitives::Algorithm as IdentityAlgorithm;
use reallyme_crypto::core::Algorithm as CryptoAlgorithm;
use reallyme_crypto::dispatch::{generate_keypair, public_key_to_multikey};
use zeroize::Zeroizing;

use crate::error::{CanonicalStateViolation, DidCoreError};

/// Convert identity algorithm → crypto algorithm.
///
/// This mapping is *intentionally explicit*.
/// DID Core is the ONLY layer allowed to do this.
fn map_identity_to_crypto_alg(alg: IdentityAlgorithm) -> Result<CryptoAlgorithm, DidCoreError> {
    match alg {
        IdentityAlgorithm::Ed25519 => Ok(CryptoAlgorithm::Ed25519),
        IdentityAlgorithm::P256 => Ok(CryptoAlgorithm::P256),
        IdentityAlgorithm::Secp256k1 => Ok(CryptoAlgorithm::Secp256k1),
        IdentityAlgorithm::MlDsa87 => Ok(CryptoAlgorithm::MlDsa87),
        IdentityAlgorithm::X25519 => Ok(CryptoAlgorithm::X25519),
        IdentityAlgorithm::MlKem768 => Ok(CryptoAlgorithm::MlKem768),
        IdentityAlgorithm::MlKem1024 => Ok(CryptoAlgorithm::MlKem1024),
    }
}

/// Generate a keypair for a DID algorithm.
pub fn generate_keypair_for_algorithm(
    alg: IdentityAlgorithm,
) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), DidCoreError> {
    let crypto_alg = map_identity_to_crypto_alg(alg)?;
    let (public_key, secret_key) = generate_keypair(crypto_alg).map_err(|_| {
        DidCoreError::InvalidCanonicalState(CanonicalStateViolation::KeypairGeneration)
    })?;
    Ok((public_key, secret_key))
}

/// Encode a public key as multikey for a DID algorithm.
pub fn public_key_to_multikey_for_algorithm(
    alg: IdentityAlgorithm,
    public: &[u8],
) -> Result<String, DidCoreError> {
    let crypto_alg = map_identity_to_crypto_alg(alg)?;
    public_key_to_multikey(crypto_alg, public)
        .map_err(|_| DidCoreError::InvalidCanonicalState(CanonicalStateViolation::MultikeyEncoding))
}
