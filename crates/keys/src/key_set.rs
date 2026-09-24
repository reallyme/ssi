// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::collections::BTreeMap;
use std::fmt;

use crate::{PrivateKeyMaterial, PublicKeyMultibase, VerificationMethodId};

/// In-memory key storage used by identity creation and rotation workflows.
///
/// Private material is stored in zeroizing buffers and never appears in `Debug`
/// output. The maps are ordered so export serialization is deterministic across
/// processes and platforms, which matters for reproducible tests and audited
/// fixtures.
#[derive(Default)]
pub struct KeySet {
    pub(crate) private_keys: BTreeMap<VerificationMethodId, PrivateKeyMaterial>,
    pub(crate) public_keys: BTreeMap<VerificationMethodId, PublicKeyMultibase>,
}

impl KeySet {
    /// Create an empty key set.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl fmt::Debug for KeySet {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("KeySet")
            .field("private_key_count", &self.private_keys.len())
            .field("public_key_count", &self.public_keys.len())
            .finish()
    }
}
