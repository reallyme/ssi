// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use core::fmt;

use crate::{enforce_limits, WebDeliveryError, WebLimits};
use identity_presentation_delivery_core::{DeliveryEnvelope, DeliveryError, DeliveryPayload};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// QR payload output.
#[derive(PartialEq, Eq)]
pub enum QrPayload {
    /// A raw string to embed in QR.
    Text(String),

    /// A URL string (useful for deep links).
    Url(String),
}

impl fmt::Debug for QrPayload {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("QrPayload([REDACTED])")
    }
}

impl Zeroize for QrPayload {
    fn zeroize(&mut self) {
        match self {
            Self::Text(value) | Self::Url(value) => value.zeroize(),
        }
    }
}

impl Drop for QrPayload {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for QrPayload {}

/// Build a QR payload string from a delivery envelope.
///
/// This:
/// - enforces expiry and size constraints
/// - returns a string suitable for embedding in a QR code generator
pub fn build_qr_payload(
    env: &DeliveryEnvelope,
    now_unix: u64,
    limits: &WebLimits,
) -> Result<QrPayload, WebDeliveryError> {
    enforce_limits(env, now_unix, limits)?;

    match &env.payload {
        DeliveryPayload::Text(s) => Ok(QrPayload::Text(s.clone())),

        DeliveryPayload::Bytes(b) => {
            // Encode bytes into base64url to survive QR text channels.
            let s = codec_base64url::bytes_to_base64url(b);

            if s.len() > limits.max_qr_bytes {
                return Err(DeliveryError::PayloadTooLarge.into());
            }

            Ok(QrPayload::Text(s))
        }
    }
}
