// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::{WebDeliveryError, WebLimits};
use identity_presentation_delivery_core::DeliveryError;
use url::Url;

/// URI schemes accepted as deep-link bases.
///
/// - `https`: universal / app links and web fallbacks
/// - `openid4vp`: OpenID for Verifiable Presentations wallet invocation
/// - `haip`: OpenID4VC High Assurance Interoperability Profile invocation
/// - `openid-credential-offer`: OpenID for Verifiable Credential Issuance offers
/// - `eudi-openid4vp`: EUDI Wallet OpenID4VP invocation
pub const ALLOWED_DEEP_LINK_SCHEMES: &[&str] = &[
    "https",
    "openid4vp",
    "haip",
    "openid-credential-offer",
    "eudi-openid4vp",
];

/// Build a deep link URL with query parameters.
///
/// The base must use one of [`ALLOWED_DEEP_LINK_SCHEMES`], must not carry
/// userinfo, and `https` bases must name a host. Size limits are enforced on
/// the untrusted inputs before parsing and on the final URL.
///
/// Example:
/// - base: <https://wallet.example/import>
/// - params: [("payload", "...")]
pub fn build_deep_link(
    base: &str,
    params: &[(&str, &str)],
    limits: &WebLimits,
) -> Result<String, WebDeliveryError> {
    let input_bytes = params
        .iter()
        .try_fold(base.len(), |total, (key, value)| {
            total
                .checked_add(key.len())
                .and_then(|sum| sum.checked_add(value.len()))
        })
        .ok_or(DeliveryError::PayloadTooLarge)?;
    if input_bytes > limits.max_url_bytes {
        return Err(DeliveryError::PayloadTooLarge.into());
    }

    let mut url = Url::parse(base).map_err(|_| WebDeliveryError::InvalidUrl)?;
    validate_deep_link_base(&url)?;

    {
        let mut qp = url.query_pairs_mut();
        for (k, v) in params {
            qp.append_pair(k, v);
        }
    }

    let s = url.to_string();
    if s.len() > limits.max_url_bytes {
        return Err(DeliveryError::PayloadTooLarge.into());
    }

    Ok(s)
}

fn validate_deep_link_base(url: &Url) -> Result<(), WebDeliveryError> {
    if !ALLOWED_DEEP_LINK_SCHEMES.contains(&url.scheme()) {
        return Err(WebDeliveryError::InvalidUrl);
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(WebDeliveryError::InvalidUrl);
    }
    if url.scheme() == "https" && url.host_str().is_none_or(str::is_empty) {
        return Err(WebDeliveryError::InvalidUrl);
    }
    Ok(())
}
