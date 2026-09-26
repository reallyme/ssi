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
//! SIOP v2 request and response primitives.
//!
//! This crate owns the transport-neutral SIOP data model and request lifetime
//! checks. Signature verification and key resolution live in the verifier crate
//! so policy and protocol callers can choose their own resolver boundary.

mod build;
mod error;
mod model;

pub use build::{
    build_siop_authentication_request, validate_siop_authentication_request,
    BuildSiopAuthenticationRequestInput, MAX_SIOP_REQUEST_LIFETIME_SECONDS, MAX_SIOP_SCOPES,
    MAX_SIOP_SCOPE_BYTES, MAX_SIOP_TEXT_BYTES, SIOP_NONCE_BYTES,
};
pub use error::SiopDeliveryError;
pub use model::{
    SiopAuthenticationRequest, SiopAuthenticationResponse, SiopIdTokenClaims, SiopSubjectJwk,
};
