// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(missing_docs)]

//! Committed-claim credential processing.
//!
//! This module extends the package-owned credential model with deterministic
//! Merkle-committed issuance, proof binding, signed-envelope transport, and
//! cryptographic verification. Network I/O and protocol orchestration remain
//! outside `reallyme-credential`.

pub mod canonical;
pub mod error;
pub mod model;

#[cfg(any(feature = "native", feature = "wasm"))]
pub mod proof_binding;

#[cfg(any(feature = "native", feature = "wasm"))]
pub mod issue;

#[cfg(any(feature = "native", feature = "wasm"))]
pub mod verify;

#[cfg(any(feature = "native", feature = "wasm"))]
pub mod signed_envelope;
