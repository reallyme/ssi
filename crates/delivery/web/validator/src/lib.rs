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

//! Web / non-OIDC VP validator.
//!
//! This crate is the verifier-grade boundary for direct web, QR, and wallet-link
//! presentation delivery. Protocol-specific OpenID response assembly stays in
//! OpenID4VP; this crate verifies the presentation and applies identity policy.

/// Web delivery presentation validator.
pub mod validator;

pub use validator::{validate_web_presentation, WebValidationInput, WebValidationResult};
