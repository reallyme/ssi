// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use core::fmt;

use crate::{WebDeliveryError, WebLimits};
use identity_presentation_delivery_core::{DeliveryError, DeliveryPayload};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Config for building Google Wallet "Save" URLs.
#[derive(Debug, Clone)]
pub struct GoogleWalletSaveConfig {
    /// Default:
    /// <https://pay.google.com/gp/v/save/>
    pub save_url_prefix: String,
}

impl Default for GoogleWalletSaveConfig {
    fn default() -> Self {
        Self {
            save_url_prefix: "https://pay.google.com/gp/v/save/".into(),
        }
    }
}

/// Injected signer for Google Wallet JWT payload.
pub trait GoogleWalletJwtSigner {
    /// Sign a Google Wallet payload JSON document as a compact JWT.
    fn sign_jwt(&self, payload_json: &[u8]) -> Result<String, WebDeliveryError>;
}

/// Sensitive Google Wallet save URL containing a compact bearer JWT.
pub struct GoogleWalletSaveLink {
    value: String,
}

impl GoogleWalletSaveLink {
    /// Borrows the complete URL for immediate delivery to the wallet surface.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.value
    }
}

impl fmt::Debug for GoogleWalletSaveLink {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GoogleWalletSaveLink([REDACTED])")
    }
}

impl Zeroize for GoogleWalletSaveLink {
    fn zeroize(&mut self) {
        self.value.zeroize();
    }
}

impl Drop for GoogleWalletSaveLink {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for GoogleWalletSaveLink {}

/// Build a Google Wallet "Save" URL from a delivery payload.
pub fn build_google_wallet_save_link(
    payload: &DeliveryPayload,
    signer: &dyn GoogleWalletJwtSigner,
    cfg: &GoogleWalletSaveConfig,
    limits: &WebLimits,
) -> Result<GoogleWalletSaveLink, WebDeliveryError> {
    let json_bytes = match payload {
        DeliveryPayload::Bytes(b) => b.as_slice(),
        DeliveryPayload::Text(s) => s.as_bytes(),
    };

    if json_bytes.len() > limits.max_url_bytes {
        return Err(DeliveryError::PayloadTooLarge.into());
    }

    let jwt = Zeroizing::new(signer.sign_jwt(json_bytes)?);
    let url_bytes = cfg
        .save_url_prefix
        .len()
        .checked_add(jwt.len())
        .ok_or(DeliveryError::PayloadTooLarge)?;
    if url_bytes > limits.max_url_bytes {
        return Err(DeliveryError::PayloadTooLarge.into());
    }

    let mut value = String::with_capacity(url_bytes);
    value.push_str(&cfg.save_url_prefix);
    value.push_str(&jwt);
    Ok(GoogleWalletSaveLink { value })
}
