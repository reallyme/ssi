// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_codec::base64::base64_to_bytes;

use crate::{
    ExportedKeySet, KeySet, KeySetError, PrivateKeyMaterial, PublicKeyMultibase,
    VerificationMethodId,
};

impl KeySet {
    /// Import from a JSON-compatible representation.
    ///
    /// Malformed private key encodings now fail the whole import instead of
    /// being silently skipped. Silent drops are dangerous for rotation and
    /// recovery flows because they can make a partially imported key set look
    /// valid until signing fails later.
    pub fn import(mut exported: ExportedKeySet) -> Result<Self, KeySetError> {
        let mut key_set = KeySet::new();

        for (id, private_key_base64) in core::mem::take(&mut exported.private) {
            let id = VerificationMethodId::new(id)?;
            let private_key = base64_to_bytes(private_key_base64.as_str())
                .map_err(|_| KeySetError::InvalidPrivateKeyEncoding)?;
            let private_key = PrivateKeyMaterial::new(private_key)?;

            key_set.put_private_material(id, private_key);
        }

        for (id, public_key_multibase) in core::mem::take(&mut exported.public) {
            let id = VerificationMethodId::new(id)?;
            let public_key = PublicKeyMultibase::new(public_key_multibase)?;

            key_set.public_keys.insert(id, public_key);
        }

        Ok(key_set)
    }
}
