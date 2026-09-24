// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use identity_presentation_delivery_core::{DeliveryEnvelope, DeliveryError, DeliveryPayload};

/// Size and expiry constraints for web delivery.
#[derive(Debug, Clone)]
pub struct WebLimits {
    /// Maximum bytes allowed in a QR payload.
    pub max_qr_bytes: usize,

    /// Maximum bytes allowed in a URL.
    pub max_url_bytes: usize,
}

impl Default for WebLimits {
    fn default() -> Self {
        Self {
            // Conservative: most QR scanners tolerate more, but keep safe by default.
            max_qr_bytes: 2048,
            max_url_bytes: 4096,
        }
    }
}

/// Enforce expiry and size limits for a delivery envelope.
pub fn enforce_limits(
    env: &DeliveryEnvelope,
    now_unix: u64,
    limits: &WebLimits,
) -> Result<(), DeliveryError> {
    if let Some(exp) = env.expires_at {
        if now_unix > exp {
            return Err(DeliveryError::Expired);
        }
    }

    let size = match &env.payload {
        DeliveryPayload::Bytes(b) => b.len(),
        DeliveryPayload::Text(s) => s.len(),
    };

    if size > limits.max_qr_bytes {
        return Err(DeliveryError::PayloadTooLarge);
    }

    Ok(())
}
