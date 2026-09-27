// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use core::fmt;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::sensitive::zeroize_json_value;

/// SD-JWT disclosure payload.
///
/// The disclosure JSON array shape is `[salt, key, value]`.
#[derive(Serialize, Deserialize, PartialEq)]
pub struct SdJwtDisclosure {
    /// Base64url-encoded disclosure salt.
    pub salt_b64u: String,
    /// Object-property name authenticated by this disclosure.
    pub key: String,
    /// JSON value revealed by the disclosure.
    pub value: Value,
}

impl fmt::Debug for SdJwtDisclosure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SdJwtDisclosure([REDACTED])")
    }
}

impl Zeroize for SdJwtDisclosure {
    fn zeroize(&mut self) {
        self.salt_b64u.zeroize();
        self.key.zeroize();
        zeroize_json_value(&mut self.value);
    }
}

impl Drop for SdJwtDisclosure {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for SdJwtDisclosure {}
