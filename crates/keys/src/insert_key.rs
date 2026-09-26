// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::{KeySet, KeySetError, PrivateKeyMaterial, PublicKeyMultibase, VerificationMethodId};
use zeroize::Zeroizing;

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

        self.public_keys.insert(id, public_key);

        Ok(())
    }

    pub(crate) fn put_private_material(
        &mut self,
        id: VerificationMethodId,
        private_key: PrivateKeyMaterial,
    ) {
        self.private_keys.insert(id, private_key);
    }
}
