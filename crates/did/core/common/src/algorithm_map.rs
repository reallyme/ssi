// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Centralized algorithm mapping.
//!
//! ## Design principles
//!
//! * `Algorithm` is **semantic** — it has no inherent string form.
//! * String representations are **namespace-specific vocabulary**.
//! * Proto enums are **wire format only** and must never leak to JSON.
//!
//! This file is the *only* place where algorithm spellings are defined.
//!
//! ### Supported namespaces
//!
//! | Namespace | Purpose | Canonical form |
//! |------------------|----------------------------------------|----------------|
//! | DID / policy | DID Documents, UpdatePolicy, EU ID 2.0 | `Ed25519`, `P-256` |
//! | VC / JOSE | JWS, JWT, VC proofs | `EdDSA`, `ES256` |
//!
//! Call sites **must explicitly choose** the namespace they emit.

use crate::{Algorithm, IdentityCoreError};

// ============================================================
// DID strings → Semantic Algorithm
// ============================================================

/// Parse a canonical DID/policy algorithm string into a semantic `Algorithm`.
///
/// Algorithm namespaces are intentionally not interchangeable. Accepting JOSE
/// names or casing aliases here makes a malformed DID document appear valid
/// and prevents callers from detecting contract drift.
pub fn alg_str_to_alg(s: &str) -> Result<Algorithm, IdentityCoreError> {
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

/// Parse a **VC / JOSE** algorithm string into a semantic `Algorithm`.
///
/// This parser is intentionally **strict**: it only accepts the canonical VC/JOSE spellings.
/// Use this at verification boundaries that must not accept curve / key-type names.
pub fn vc_alg_str_to_alg(s: &str) -> Result<Algorithm, IdentityCoreError> {
    match s {
        "EdDSA" => Ok(Algorithm::Ed25519),
        "ES256" => Ok(Algorithm::P256),
        "ES256K" => Ok(Algorithm::Secp256k1),
        "X25519" => Ok(Algorithm::X25519),
        "ML-DSA-87" => Ok(Algorithm::MlDsa87),
        "ML-KEM-768" => Ok(Algorithm::MlKem768),
        "ML-KEM-1024" => Ok(Algorithm::MlKem1024),
        _ => Err(IdentityCoreError::AlgorithmNotAllowed),
    }
}

// ============================================================
// Semantic Algorithm → Namespace-specific canonical strings
// ============================================================

/// Semantic Algorithm → canonical **VC / JOSE** algorithm string.
///
/// Used for:
/// * JWS / JWT headers
/// * Verifiable Credential proofs
///
/// This must never be used in DID Documents or policies.
pub fn alg_to_vc_alg_str(alg: Algorithm) -> &'static str {
    match alg {
        Algorithm::Ed25519 => "EdDSA",
        Algorithm::P256 => "ES256",
        Algorithm::Secp256k1 => "ES256K",
        Algorithm::X25519 => "X25519",
        Algorithm::MlDsa87 => "ML-DSA-87",
        Algorithm::MlKem768 => "ML-KEM-768",
        Algorithm::MlKem1024 => "ML-KEM-1024",
    }
}

/// Semantic Algorithm → canonical **DID / policy** algorithm string.
///
/// Used for:
/// * DID Documents
/// * UpdatePolicy
/// * EU ID 2.0 DID profiles
///
/// These spellings are DID-native and intentionally
/// differ from VC / JOSE terminology.
pub fn alg_to_did_alg_str(alg: Algorithm) -> &'static str {
    match alg {
        Algorithm::Ed25519 => "Ed25519",
        Algorithm::X25519 => "X25519",
        Algorithm::P256 => "P-256",
        Algorithm::Secp256k1 => "secp256k1",
        Algorithm::MlDsa87 => "ML-DSA-87",
        Algorithm::MlKem768 => "ML-KEM-768",
        Algorithm::MlKem1024 => "ML-KEM-1024",
    }
}

#[cfg(test)]
#[path = "algorithm_map_tests.rs"]
mod tests;
