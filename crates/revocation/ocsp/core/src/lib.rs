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

//! OCSP-based revocation checking (portable core).
//!
//! Overview: OCSP semantics and integration points for trust evaluation.
//!
//! Non-goals:
//! - Fetching OCSP responses.
//! - ASN.1 parsing.
//! - Signature verification.
//!
//! Backends (OpenSSL, WASM, Swift, Kotlin) produce `ParsedOcspResponse`.

/// Portable OCSP status checker.
pub mod checker;
/// Typed OCSP evaluation errors.
pub mod error;
/// Parsed OCSP response model and policy knobs.
pub mod model;

pub use checker::OcspChecker;
pub use error::OcspError;
pub use model::{
    OcspCertStatus, OcspExtension, OcspPolicy, ParsedOcspResponse, DEFAULT_MAX_OCSP_AGE_SECS,
};
