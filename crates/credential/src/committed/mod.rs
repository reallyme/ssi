// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Committed-claim credential processing.
//!
//! This module extends the package-owned credential model with deterministic
//! Merkle-committed issuance, proof binding, signed-envelope transport, and
//! cryptographic verification. Network I/O and protocol orchestration remain
//! outside `reallyme-credential`.

/// Canonical byte encodings used by commitment and signature calculations.
pub mod canonical;
/// Typed committed-credential processing errors.
pub mod error;
/// Public committed-credential envelopes, proofs, and private subject material.
pub mod model;

/// Binding between an issuer signature, commitment root, and subject key.
#[cfg(any(feature = "native", feature = "wasm"))]
pub mod proof_binding;

/// Committed-credential issuance.
#[cfg(any(feature = "native", feature = "wasm"))]
pub mod issue;

/// Issuance when an issuer has independently approved an external commitment.
#[cfg(any(feature = "native", feature = "wasm"))]
pub mod precomputed_commitment;

/// Committed-credential verification.
#[cfg(any(feature = "native", feature = "wasm"))]
pub mod verify;

/// Deterministic signed-envelope CBOR encoding and decoding.
#[cfg(any(feature = "native", feature = "wasm"))]
pub mod signed_envelope;
