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

pub mod error;
pub use error::VcJwtError;

mod vc_jwt;
pub use vc_jwt::{decode_verify_vc_jwt, encode_vc_jwt, encode_vc_jwt_with_signer, VcJwtPayload};
