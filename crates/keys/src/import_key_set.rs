// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_codec::base64::base64_to_bytes;
use zeroize::Zeroizing;

use crate::{ExportedKeySet, KeySet, KeySetError};

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
            let public_key = exported
                .public
                .remove(&id)
                .ok_or(KeySetError::MissingPublicKey)?;
            let private_key = Zeroizing::new(
                base64_to_bytes(private_key_base64.as_str())
                    .map_err(|_| KeySetError::InvalidPrivateKeyEncoding)?,
            );
            key_set.put_key_zeroizing(id, private_key, public_key)?;
        }

        for (id, public_key_multibase) in core::mem::take(&mut exported.public) {
            key_set.put_public(id, public_key_multibase)?;
        }

        Ok(key_set)
    }
}
