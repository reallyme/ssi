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

//! Protocol-agnostic VP validation (policy/semantic).
//!
//! This crate does **not** perform cryptographic verification of VC/VP proofs.
//! Instead, it validates a parsed Presentation against the selected policy
//! using caller-supplied cryptographic *facts* (e.g. algorithms used),
//! status context, QEAA context, and a binding result.

/// Typed VP validation errors.
pub mod error;
/// Stable OIDC error mapping for VP validation failures.
pub mod oidc_error;
pub mod validator;

pub use error::VpValidationError;
pub use validator::{validate_presentation, CryptoContext, QeaaContext, VpValidationInput};
