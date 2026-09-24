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
//! SIOP v2 ID token verification.
//!
//! This crate verifies JWT signatures and enforces SIOP replay bindings
//! against the originating authentication request. Key lookup is injected via
//! `SiopKeyResolver` to keep resolver policy outside the protocol verifier.

mod error;
mod verifier;

pub use error::SiopVerifierError;
pub use verifier::{
    verify_siop_authentication_response, verify_siop_id_token_jwt, SiopKeyResolver,
    VerifiedSiopIdToken, MAX_SIOP_AUDIENCES, MAX_SIOP_ID_TOKEN_BYTES, MAX_SIOP_KEY_ID_BYTES,
    MAX_SIOP_PROTECTED_HEADER_BYTES,
};
