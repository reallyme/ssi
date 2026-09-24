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

//! Identity delivery core.
//!
//! Overview: Transport-neutral models for delivering credentials or presentations across channels
//! (web, QR, wallet links, native handoff, etc.).
//!
//! Scope:
//! - Data models and helpers that are independent of cryptography, policy, and storage.
//!
//! Non-goals:
//! - Cryptography, policy decisions, VC/VP semantics, and I/O.

/// Transport-neutral delivery data model.
pub mod model;
pub use model::{DeliveryEnvelope, DeliveryIntent, DeliveryPayload, DeliveryTarget};

/// Delivery-core typed errors.
pub mod error;
pub use error::DeliveryError;
