// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::{KeySet, KeySetError, PrivateKeyMaterial, VerificationMethodId};
use zeroize::Zeroizing;

impl KeySet {
    /// Borrow private key material for cryptographic use.
    pub fn private_key(&self, id: &str) -> Result<&PrivateKeyMaterial, KeySetError> {
        let id = VerificationMethodId::new(id)?;

        self.private_keys
            .get(&id)
            .ok_or(KeySetError::MissingPrivateKey)
    }

    /// Return an owned private key copy for adapters that require ownership.
    ///
    /// Prefer `private_key` where possible to avoid duplicating secret bytes.
    pub fn get_private(&self, id: &str) -> Result<Zeroizing<Vec<u8>>, KeySetError> {
        Ok(self.private_key(id)?.to_vec())
    }

    /// Borrow the public key multibase string for a verification method.
    pub fn public_key(&self, id: &str) -> Result<&str, KeySetError> {
        let id = VerificationMethodId::new(id)?;

        self.public_keys
            .get(&id)
            .map(crate::PublicKeyMultibase::as_str)
            .ok_or(KeySetError::MissingPublicKey)
    }

    /// Return an owned public key multibase string.
    pub fn get_public(&self, id: &str) -> Result<String, KeySetError> {
        Ok(self.public_key(id)?.to_owned())
    }
}
