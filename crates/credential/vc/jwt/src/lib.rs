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
// This source-only support crate is consumed through the root identity facade.
// Keep workspace missing-docs enforcement active by default while avoiding
// filler rustdoc on transitional JWT-VC adapter fields.
#![allow(missing_docs)]

//! Legacy credential-model JWT adapter.
//!
//! [`VcJwtPayload`] serializes the package-owned credential model for existing
//! ReallyMe integrations. It is a distinct wire profile from the W3C JWT-VC
//! envelope exposed by `envelopes-jwt-vc`; payloads must be decoded and
//! verified by the profile that issued them. Applications must not select a
//! decoder by trying both formats after signature or claim validation fails.

pub mod error;
pub use error::VcJwtError;

mod validate_temporal;
mod vc_jwt;
pub use validate_temporal::{VcJwtVerificationOptions, MAX_VC_JWT_CLOCK_SKEW_SECONDS};
pub use vc_jwt::{decode_verify_vc_jwt, encode_vc_jwt, encode_vc_jwt_with_signer, VcJwtPayload};
