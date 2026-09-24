// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// What is being carried over NFC/BLE contact channel.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Zeroize)]
#[serde(rename_all = "snake_case")]
pub enum ContactPayloadKind {
    /// A protocol "engagement" payload (e.g., initial handover bytes).
    Engagement,

    /// A request payload (e.g., OpenID4VP request).
    Request,

    /// A response payload (e.g., mdoc DeviceResponse CBOR).
    Response,
}

/// Transport-neutral NFC/BLE message (CBOR encoded).
///
/// Security model:
/// - This layer DOES NOT sign the payload.
/// - It binds the payload to a session transcript via `session_transcript_sha256`.
/// - Higher layers should still verify signatures (mdoc/OpenID4VP/JWT/etc).
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct ContactMessage {
    /// Contact delivery format version.
    pub version: String,

    /// Protocol role of the embedded payload.
    pub kind: ContactPayloadKind,

    /// 16-byte session identifier (derived from transcript by default).
    pub session_id: Vec<u8>,

    /// sha256(sessionTranscriptCbor)
    pub session_transcript_sha256: Vec<u8>,

    /// Deterministic identifier for this message.
    pub message_id: u32,

    /// Optional content type for the inner payload (e.g., "application/cbor").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,

    /// Unix seconds.
    pub created_at: u64,

    /// Unix seconds.
    pub expires_at: u64,

    /// Opaque inner bytes (protocol-specific).
    pub payload: Vec<u8>,
}

/// A single transport frame (CBOR encoded) for BLE/NFC fragmentation.
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct ContactFrame {
    /// Contact delivery frame format version.
    pub version: String,

    /// Session identifier shared by all frames for the message.
    pub session_id: Vec<u8>,

    /// Deterministic message identifier shared by all frames for the message.
    pub message_id: u32,

    /// 0-based sequence number.
    pub seq: u16,

    /// Total number of frames (>= 1).
    pub total: u16,

    /// Raw chunk bytes.
    pub chunk: Vec<u8>,
}

impl core::fmt::Debug for ContactMessage {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ContactMessage")
            .field("contents", &"<redacted>")
            .finish()
    }
}

impl core::fmt::Debug for ContactFrame {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ContactFrame")
            .field("contents", &"<redacted>")
            .finish()
    }
}
