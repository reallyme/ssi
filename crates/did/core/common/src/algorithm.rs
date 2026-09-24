// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use core::str::FromStr;
use serde::{Deserialize, Serialize};

use crate::IdentityCoreError;

/// Cryptographic algorithms supported by the identity system.
///
/// This enum represents **semantic algorithms**, not encodings,
/// spellings, namespaces, or wire formats.
///
/// Design rules:
/// - No string literals beyond canonical identity meaning
/// - No VC / JOSE / DID / Proto knowledge
/// - No wire or serialization vocabulary
///
/// All external representations MUST be handled by
/// `algorithm_map.rs`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Algorithm {
    /// Ed25519 signing keys.
    Ed25519,

    /// X25519 key agreement keys.
    X25519,

    /// NIST P-256 signing keys.
    P256,

    /// secp256k1 signing keys.
    Secp256k1,

    /// ML-DSA-87 post-quantum signing keys.
    MlDsa87,

    /// ML-KEM-768 post-quantum KEM keys.
    MlKem768,

    /// ML-KEM-1024 post-quantum KEM keys.
    MlKem1024,
}

impl Algorithm {
    /// Canonical identity-level name.
    ///
    /// WARNING This is NOT a VC/JWS or proto string.
    /// It is only suitable for internal diagnostics or logging.
    pub fn canonical_name(&self) -> &'static str {
        match self {
            Algorithm::Ed25519 => "Ed25519",
            Algorithm::X25519 => "X25519",
            Algorithm::P256 => "P-256",
            Algorithm::Secp256k1 => "secp256k1",
            Algorithm::MlDsa87 => "ML-DSA-87",
            Algorithm::MlKem768 => "ML-KEM-768",
            Algorithm::MlKem1024 => "ML-KEM-1024",
        }
    }
}

/// STRICT parsing only.
///
/// This intentionally accepts **only canonical identity spellings**.
/// All tolerant / external parsing belongs in `algorithm_map.rs`.
impl FromStr for Algorithm {
    type Err = IdentityCoreError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "Ed25519" => Ok(Algorithm::Ed25519),
            "X25519" => Ok(Algorithm::X25519),
            "P-256" => Ok(Algorithm::P256),
            "secp256k1" => Ok(Algorithm::Secp256k1),
            "ML-DSA-87" => Ok(Algorithm::MlDsa87),
            "ML-KEM-768" => Ok(Algorithm::MlKem768),
            "ML-KEM-1024" => Ok(Algorithm::MlKem1024),
            _ => Err(IdentityCoreError::AlgorithmNotAllowed),
        }
    }
}

/// Ergonomic strict conversion with error message.
impl TryFrom<&str> for Algorithm {
    type Error = IdentityCoreError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        Algorithm::from_str(s)
    }
}

/// Canonical identity string conversion.
///
/// WARNING This must NOT be used for VC / JOSE / DID output.
impl From<Algorithm> for &'static str {
    fn from(a: Algorithm) -> Self {
        a.canonical_name()
    }
}
