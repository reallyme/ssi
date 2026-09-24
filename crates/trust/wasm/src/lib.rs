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

//! WASM-compatible trust verification helpers.
//!
//! This crate provides portable certificate signature verification and TSL
//! trust evaluation for environments where OpenSSL or xmlsec backends are not
//! available.

#[cfg(all(feature = "native", target_arch = "wasm32"))]
compile_error!("identity-trust-wasm: `native` feature must not be enabled for wasm32");

/// TSL parsing and preverified XMLDSig trust checks.
pub mod tsl;
/// Pure-Rust certificate signature verifier for WASM/mobile lanes.
pub mod verifier;

pub use tsl::{verify_tsl_xml_wasm, TslWasmError};
pub use verifier::WasmSignatureVerifier;
