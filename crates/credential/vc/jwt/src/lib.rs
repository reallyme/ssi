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
//! Legacy credential-model JWT adapter.
//!
//! [`VcJwtPayload`] serializes the package-owned credential model for existing
//! ReallyMe integrations. It is a distinct wire profile from the canonical
//! credential-envelope JWT wrapper exposed by `envelopes-jwt-vc`; payloads must be decoded and
//! verified by the profile that issued them. Applications must not select a
//! decoder by trying both formats after signature or claim validation fails.

/// Typed JWT-VC encoding, decoding, and verification errors.
pub mod error;
pub use error::VcJwtError;

mod validate_temporal;
mod vc_jwt;
pub use validate_temporal::{VcJwtVerificationOptions, MAX_VC_JWT_CLOCK_SKEW_SECONDS};
pub use vc_jwt::{decode_verify_vc_jwt, encode_vc_jwt, encode_vc_jwt_with_signer, VcJwtPayload};
