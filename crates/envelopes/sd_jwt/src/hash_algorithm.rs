// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_crypto::core::HashAlgorithm;

use crate::SdJwtEnvelopeError;

const SD_JWT_SHA_256: &str = "sha-256";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SdJwtHashAlgorithm {
    Sha256,
}

impl SdJwtHashAlgorithm {
    pub const fn default_for_sd_jwt() -> Self {
        SdJwtHashAlgorithm::Sha256
    }

    pub const fn name(self) -> &'static str {
        match self {
            SdJwtHashAlgorithm::Sha256 => SD_JWT_SHA_256,
        }
    }

    pub(crate) const fn dispatch_algorithm(self) -> HashAlgorithm {
        match self {
            SdJwtHashAlgorithm::Sha256 => HashAlgorithm::Sha2_256,
        }
    }

    pub fn parse(value: &str) -> Result<Self, SdJwtEnvelopeError> {
        match value {
            SD_JWT_SHA_256 => Ok(SdJwtHashAlgorithm::Sha256),
            _ => Err(SdJwtEnvelopeError::UnsupportedHashAlgorithm),
        }
    }
}
