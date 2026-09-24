// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::{WebDeliveryError, WebLimits};
use url::Url;

/// Build a deep link URL with query parameters.
///
/// Example:
/// - base: <https://wallet.example/import>
/// - params: [("payload", "...")]
pub fn build_deep_link(
    base: &str,
    params: &[(&str, &str)],
    limits: &WebLimits,
) -> Result<String, WebDeliveryError> {
    let mut url = Url::parse(base).map_err(|_| WebDeliveryError::InvalidUrl)?;

    {
        let mut qp = url.query_pairs_mut();
        for (k, v) in params {
            qp.append_pair(k, v);
        }
    }

    let s = url.to_string();
    if s.len() > limits.max_url_bytes {
        return Err(WebDeliveryError::Delivery(
            identity_presentation_delivery_core::DeliveryError::PayloadTooLarge,
        ));
    }

    Ok(s)
}
