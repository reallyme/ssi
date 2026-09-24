// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::collections::BTreeMap;

use reallyme_codec::base64::bytes_to_base64;

use crate::{ExportedKeySet, ExportedPrivateKey, KeySet};

impl KeySet {
    /// Export to a JSON-compatible representation.
    ///
    /// Private keys are base64 encoded to preserve byte-for-byte round trips
    /// through JSON. The returned maps are ordered for deterministic
    /// serialization.
    #[must_use]
    pub fn export(&self) -> ExportedKeySet {
        let mut private = BTreeMap::new();
        let mut public = BTreeMap::new();

        for (id, private_key) in &self.private_keys {
            private.insert(
                id.as_str().to_owned(),
                ExportedPrivateKey::new(bytes_to_base64(private_key.expose_secret())),
            );
        }

        for (id, public_key) in &self.public_keys {
            public.insert(id.as_str().to_owned(), public_key.as_str().to_owned());
        }

        ExportedKeySet { private, public }
    }
}
