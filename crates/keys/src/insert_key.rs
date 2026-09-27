// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::{KeySet, KeySetError, PrivateKeyMaterial, PublicKeyMultibase, VerificationMethodId};
use zeroize::Zeroizing;

fn validate_key_pair(
    private_key: &PrivateKeyMaterial,
    public_key: &PublicKeyMultibase,
) -> Result<(), KeySetError> {
    let parsed = reallyme_codec::multikey::parse_multikey(public_key.as_str())
        .map_err(|_| KeySetError::InvalidPublicKeyMultibase)?;
    let secret = private_key.expose_secret();
    let secret_32 =
        || <&[u8; 32]>::try_from(secret).map_err(|_| KeySetError::InvalidPrivateKeyMaterial);
    let secret_64 =
        || <&[u8; 64]>::try_from(secret).map_err(|_| KeySetError::InvalidPrivateKeyMaterial);
    let derived = match parsed.codec_name {
        "ed25519-pub" => reallyme_crypto::ed25519::generate_ed25519_keypair_from_seed(secret_32()?)
            .map(|pair| pair.0),
        "p256-pub" => reallyme_crypto::p256::generate_p256_keypair_from_secret_key(secret_32()?)
            .map(|pair| pair.0),
        "secp256k1-pub" => {
            reallyme_crypto::secp256k1::generate_secp256k1_keypair_from_secret_key(secret_32()?)
                .map(|pair| pair.0)
        }
        "x25519-pub" => reallyme_crypto::x25519::generate_x25519_keypair_from_seed(secret_32()?)
            .map(|pair| pair.0),
        "mldsa-87-pub" => {
            reallyme_crypto::ml_dsa_87::generate_ml_dsa_87_keypair_from_seed(secret_32()?)
                .map(|pair| pair.0)
        }
        "mlkem-768-pub" => {
            reallyme_crypto::ml_kem_768::generate_ml_kem_768_keypair_from_seed(secret_64()?)
                .map(|pair| pair.0)
        }
        "mlkem-1024-pub" => {
            reallyme_crypto::ml_kem_1024::generate_ml_kem_1024_keypair_from_seed(secret_64()?)
                .map(|pair| pair.0)
        }
        _ => return Err(KeySetError::UnsupportedKeyPairAlgorithm),
    }
    .map_err(|_| KeySetError::InvalidPrivateKeyMaterial)?;

    if !reallyme_crypto::operations::constant_time::equal(&derived, &parsed.public_key) {
        return Err(KeySetError::KeyPairMismatch);
    }
    Ok(())
}

impl KeySet {
    /// Insert or overwrite a full key pair.
    ///
    /// The private bytes are moved into a zeroizing owner before any other
    /// input is validated, so every validation failure zeroizes them on the
    /// way out. Existing entries are also zeroized when overwritten.
    pub fn put_key(
        &mut self,
        id: impl Into<String>,
        private_key: Vec<u8>,
        public_key_multibase: impl Into<String>,
    ) -> Result<(), KeySetError> {
        self.put_key_zeroizing(id, Zeroizing::new(private_key), public_key_multibase)
    }

    /// Insert or overwrite a generated key pair without leaving zeroizing
    /// private-key ownership.
    ///
    /// # Errors
    ///
    /// Returns [`KeySetError`] when the verification-method identifier, private
    /// key material, or public Multikey is invalid.
    pub fn put_key_zeroizing(
        &mut self,
        id: impl Into<String>,
        private_key: Zeroizing<Vec<u8>>,
        public_key_multibase: impl Into<String>,
    ) -> Result<(), KeySetError> {
        let id = VerificationMethodId::new(id)?;
        let private_key = PrivateKeyMaterial::new_zeroizing(private_key)?;
        let public_key = PublicKeyMultibase::new(public_key_multibase)?;
        validate_key_pair(&private_key, &public_key)?;

        self.private_keys.insert(id.clone(), private_key);
        self.public_keys.insert(id, public_key);

        Ok(())
    }

    /// Store or overwrite only the public key for a verification method.
    ///
    /// This is used during rotations where public material can arrive before
    /// private material is available in the local signer.
    pub fn put_public(
        &mut self,
        id: impl Into<String>,
        public_key_multibase: impl Into<String>,
    ) -> Result<(), KeySetError> {
        let id = VerificationMethodId::new(id)?;
        let public_key = PublicKeyMultibase::new(public_key_multibase)?;

        // Replacing a public key invalidates any private half stored under the
        // same identifier. Retaining it would make subsequent signing use a
        // key that no longer corresponds to the advertised public material.
        self.private_keys.remove(&id);
        self.public_keys.insert(id, public_key);

        Ok(())
    }
}
