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

//! CRL parsing backend (OpenSSL).
//!
//! This crate:
//! - parses CRLs (PEM / DER)
//! - verifies CRL signatures using issuer certificates
//! - extracts revoked serial numbers and metadata
//! - converts into a portable `ParsedCrl`
//!
//! It does NOT:
//! - implement revocation policy
//! - implement `StatusChecker`
//! - fetch CRLs
//! - build certificate chains
//!
//! All revocation logic lives in `identity-revocation-crl-core`.

/// Typed errors for OpenSSL-backed CRL parsing.
pub mod error;
/// PEM/DER parsing and signature verification for CRLs.
#[cfg(not(target_arch = "wasm32"))]
pub mod parse;
/// OpenSSL-backed parsed CRL model.
#[cfg(not(target_arch = "wasm32"))]
pub mod parsed_crl;

pub use error::CrlError;
#[cfg(not(target_arch = "wasm32"))]
pub use parse::{parse_crl_der_with_env_issuer, parse_crl_pem_with_env_issuer};
#[cfg(not(target_arch = "wasm32"))]
pub use parsed_crl::ParsedOpenSslCrl;

// Re-export portable core model for convenience
pub use identity_revocation_crl_core::ParsedCrl;
