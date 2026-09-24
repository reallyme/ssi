// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

/// Builders for Google Wallet object payloads.
pub mod build;
/// Minimal Google Wallet payload model.
pub mod model;
/// Save-link JWT construction.
pub mod save;
/// JWT signer implementation backed by JOSE helpers.
pub mod signer;
/// Payload validation for Google Wallet objects.
pub mod validate;

pub use build::build_generic_object;
pub use model::{GoogleWalletObject, Header, TextModule};
pub use save::{
    build_google_wallet_save_link, GoogleWalletJwtSigner, GoogleWalletSaveConfig,
    GoogleWalletSaveLink,
};
pub use signer::GoogleWalletJwtSignerImpl;
pub use validate::validate_google_wallet_payload;
