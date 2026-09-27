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

//! OpenSSL-backed OCSP verification.
//!
//! This crate:
//! - verifies OCSP response signatures using OpenSSL
//! - extracts certificate status into portable structures
//!
//! It does NOT:
//! - fetch OCSP responses
//! - decide revocation policy
//! - replace CRL or StatusList
//!
//! The issuer argument is the sole trust anchor for responder authorization.
//! Certificates supplied with a response are untrusted chain-building
//! material and cannot replace that issuer. Verification uses the caller's
//! evaluation time and rejects explicit trust shortcuts. The nonce-aware entry
//! point binds the signed response nonce to the request nonce.

#[cfg(not(target_arch = "wasm32"))]
mod bind_response;
#[cfg(not(target_arch = "wasm32"))]
mod cert_id_match;
/// Typed errors for OpenSSL-backed OCSP parsing.
pub mod error;
/// RFC 5280 issuer key identifier derivation.
#[cfg(not(target_arch = "wasm32"))]
mod issuer_key_identifier;
#[cfg(not(target_arch = "wasm32"))]
mod model;
/// DER parsing and signature verification for OCSP responses.
#[cfg(not(target_arch = "wasm32"))]
pub mod parse;

pub use error::OcspOpenSslError;
#[cfg(not(target_arch = "wasm32"))]
pub use model::VerifiedOcspResponse;
#[cfg(not(target_arch = "wasm32"))]
pub use parse::{parse_ocsp_response_der, parse_ocsp_response_der_with_nonce};
