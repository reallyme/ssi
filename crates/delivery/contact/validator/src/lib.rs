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
//! Contact delivery validators for proximity transport payloads.
//!
//! The validator reassembles and checks the transport envelope, including
//! expiry and session-transcript binding. It intentionally does not interpret
//! or trust the inner protocol payload.

mod error;
mod validator;

pub use error::ContactValidationError;
pub use validator::{
    validate_contact_frames_cbor, validate_contact_message_cbor, VerifiedContactMessage,
};
