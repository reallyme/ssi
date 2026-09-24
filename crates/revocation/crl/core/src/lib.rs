// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::print_stdout,
        clippy::print_stderr
    )
)]

//! CRL-based revocation backend (portable core).
//!
//! Implements `StatusChecker` using parsed X.509 CRLs.
//!
//! This crate:
//! - defines the portable CRL model
//! - implements CRL-based revocation checking
//!
//! It does NOT:
//! - parse CRLs (PEM / DER)
//! - verify CRL signatures
//! - depend on OpenSSL
//! - fetch CRLs
//!
//! Parsing and verification are handled by `identity-revocation-crl-openssl`.

/// Portable CRL status checker.
pub mod checker;
/// Parsed CRL model consumed by the checker.
pub mod model;

pub use checker::CrlChecker;
pub use model::ParsedCrl;
