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

//! Web delivery core.
//!
//! Overview: Transport-level helpers for web-based delivery channels (QR, links, wallet handoff).
//!
//! Scope:
//! - Deterministic construction and validation of web delivery artifacts.
//!
//! Non-goals:
//! - Cryptographic verification and policy decisions (handled in verifier and higher layers).

/// Typed errors for web delivery helpers.
pub mod error;
pub use error::WebDeliveryError;

/// Size and shape limits for web delivery artifacts.
pub mod limits;
pub use limits::{enforce_limits, WebLimits};

/// QR payload construction helpers.
pub mod qr;
pub use qr::{build_qr_payload, QrPayload};

/// Deep-link construction helpers.
pub mod links;
pub use links::build_deep_link;

/// Google Wallet save-link helpers.
pub mod google_wallet;
pub use google_wallet::{
    build_generic_object, build_google_wallet_save_link, validate_google_wallet_payload,
    GoogleWalletJwtSigner, GoogleWalletJwtSignerImpl, GoogleWalletObject, GoogleWalletSaveConfig,
    GoogleWalletSaveLink, Header, TextModule,
};
