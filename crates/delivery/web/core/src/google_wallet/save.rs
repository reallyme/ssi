// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use core::fmt;

use crate::{WebDeliveryError, WebLimits};
use identity_presentation_delivery_core::{DeliveryError, DeliveryPayload};
use url::Url;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Required scheme prefix for the Google Wallet save URL.
const REQUIRED_SAVE_URL_PREFIX_SCHEME: &str = "https://";

/// Number of dot-separated segments in a compact JWS.
const COMPACT_JWS_SEGMENTS: usize = 3;

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
    validate_save_url_prefix(&cfg.save_url_prefix, limits)?;

    let jwt = Zeroizing::new(signer.sign_jwt(json_bytes)?);
    validate_compact_jws_charset(&jwt)?;
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

/// The prefix is concatenated with the JWT verbatim, so it must be an HTTPS
/// URL with a host, no userinfo, no query or fragment, and a trailing `/`.
fn validate_save_url_prefix(prefix: &str, limits: &WebLimits) -> Result<(), WebDeliveryError> {
    if prefix.len() > limits.max_url_bytes
        || !prefix.starts_with(REQUIRED_SAVE_URL_PREFIX_SCHEME)
        || !prefix.ends_with('/')
    {
        return Err(WebDeliveryError::InvalidUrl);
    }
    let url = Url::parse(prefix).map_err(|_| WebDeliveryError::InvalidUrl)?;
    if url.scheme() != "https"
        || url.host_str().is_none_or(str::is_empty)
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(WebDeliveryError::InvalidUrl);
    }
    Ok(())
}

/// Require the signer output to be a compact JWS of three non-empty
/// base64url segments, so it cannot alter the URL structure.
fn validate_compact_jws_charset(jwt: &str) -> Result<(), WebDeliveryError> {
    let mut segments = 0_usize;
    for segment in jwt.split('.') {
        segments = segments
            .checked_add(1)
            .ok_or(WebDeliveryError::SigningFailed)?;
        if segment.is_empty()
            || !segment
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        {
            return Err(WebDeliveryError::SigningFailed);
        }
    }
    if segments != COMPACT_JWS_SEGMENTS {
        return Err(WebDeliveryError::SigningFailed);
    }
    Ok(())
}
