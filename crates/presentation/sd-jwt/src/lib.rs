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

//! Legacy ReallyMe Merkle-envelope presentation helpers.
//!
//! The five-element disclosure format and `envelope_hash` binding implemented
//! here predate RFC 9901 and are not an OpenID4VP SD-JWT VC conformance
//! surface. New standards-based integrations must use `reallyme-sd-jwt` (and
//! the OpenID4VP format adapter) instead. This compatibility crate remains for
//! existing ReallyMe Merkle-envelope records only.

/// Typed errors for SD-JWT VP helpers.
pub mod error;
pub use error::SdJwtVpError;

/// Internal disclosure item model used by SD-JWT presentation builders.
pub mod disclosure;
pub use disclosure::DisclosureItem;

/// SD-JWT VP construction helpers.
pub mod build;
pub use build::build_sd_jwt_presentation;
pub use build::{build_sd_jwt_presentation_with_kb_binding, KbJwtBindingInput};

/// SD-JWT VP verification helpers.
pub mod verify;
pub use verify::{verify_sd_jwt_vp, VerifiedDisclosure};
pub use verify::{verify_sd_jwt_vp_with_binding, ExpectedKbJwtBinding};

mod policy;
pub use policy::{extract_disclosed_claims, DisclosedClaim};
