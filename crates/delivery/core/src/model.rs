// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use zeroize::{Zeroize, ZeroizeOnDrop};

/// What is being delivered.
///
/// This is intentionally opaque to delivery-core.
/// Higher layers define meaning (VC, VP, JWT, etc).
#[derive(PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub enum DeliveryPayload {
    /// Raw bytes (e.g. JWT, CBOR, protobuf).
    Bytes(Vec<u8>),

    /// UTF-8 text (e.g. URL, compact JWT).
    Text(String),
}

/// Why the payload is being delivered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Zeroize)]
pub enum DeliveryIntent {
    /// Save to wallet.
    Store,

    /// Present to a verifier.
    Present,

    /// Share with another party.
    Share,
}

/// Where the payload is intended to go.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Zeroize)]
pub enum DeliveryTarget {
    /// Browser-based delivery (QR, link, redirect).
    Web,

    /// Native wallet app (Apple Wallet, Google Wallet).
    Wallet,

    /// Direct application-to-application handoff.
    Native,
}

/// Transport-neutral delivery envelope.
///
/// This struct is **pure data**.
/// No validation is performed automatically.
#[derive(PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct DeliveryEnvelope {
    /// What is being delivered.
    pub payload: DeliveryPayload,

    /// Why it is being delivered.
    pub intent: DeliveryIntent,

    /// Intended delivery channel.
    pub target: DeliveryTarget,

    /// Optional expiry (unix seconds).
    pub expires_at: Option<u64>,
}

impl core::fmt::Debug for DeliveryPayload {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("DeliveryPayload")
            .field("contents", &"<redacted>")
            .finish()
    }
}

impl core::fmt::Debug for DeliveryEnvelope {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("DeliveryEnvelope")
            .field("contents", &"<redacted>")
            .finish()
    }
}
