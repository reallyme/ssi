// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use core::fmt::{Debug, Formatter};

use serde::Serialize;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::{RegistrationError, RegistrationErrorReason};

const MAX_TEXT_BYTES: usize = 2_048;

/// Bounded UTF-8 protocol text with redacted diagnostics and drop zeroization.
#[derive(Eq, PartialEq, Serialize, Zeroize, ZeroizeOnDrop)]
#[serde(transparent)]
pub struct BoundedText(pub(super) String);

impl BoundedText {
    /// Copies a non-empty, NUL-free bounded string.
    pub fn try_new(value: &str) -> Result<Self, RegistrationError> {
        validate_text(value, MAX_TEXT_BYTES)?;
        Ok(Self(value.to_owned()))
    }

    /// Validates an owned string and transfers its allocation without leaving
    /// an unzeroized intermediate copy behind.
    pub(super) fn try_from_owned(value: String) -> Result<Self, RegistrationError> {
        let mut value = Zeroizing::new(value);
        validate_text(&value, MAX_TEXT_BYTES)?;
        Ok(Self(core::mem::take(&mut *value)))
    }

    /// Borrows the validated text.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl Debug for BoundedText {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("BoundedText(<redacted>)")
    }
}

pub(super) fn validate_text(value: &str, limit: usize) -> Result<(), RegistrationError> {
    if value.is_empty() || value.len() > limit || value.bytes().any(|byte| byte == 0) {
        return Err(RegistrationError::from_reason(
            RegistrationErrorReason::InvalidField,
        ));
    }
    Ok(())
}
