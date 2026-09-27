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
//! Backend crates keep verified response construction private and expose only
//! opaque receipts through the platform dispatch crate.

/// Typed OCSP evaluation errors.
pub mod error;
/// OCSP status model and policy knobs.
pub mod model;

pub use error::OcspError;
pub use model::{
    OcspCertStatus, OcspExtension, OcspPolicy, DEFAULT_MAX_OCSP_AGE_SECS, MAX_OCSP_NONCE_BYTES,
};
