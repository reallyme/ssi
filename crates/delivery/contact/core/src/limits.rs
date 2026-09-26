// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::ContactDeliveryError;

/// Absolute encoded-message ceiling enforced by the contact codec.
pub const MAX_CONTACT_MESSAGE_CBOR_BYTES: usize = 65_536;

/// Absolute encoded-frame ceiling enforced by the contact codec.
pub const MAX_CONTACT_FRAME_CBOR_BYTES: usize = 4_096;

/// Absolute frame-count ceiling enforced before allocating frame collections.
pub const MAX_CONTACT_FRAMES: usize = 1_024;

/// Required length of the transcript-derived contact session identifier.
pub const CONTACT_SESSION_ID_BYTES: usize = 16;

/// Number of digest bytes folded into the `u32` contact message identifier.
pub const CONTACT_MESSAGE_ID_BYTES: usize = 4;

/// Maximum accepted lifetime (`expires_at - created_at`) of a contact message.
///
/// Proximity handovers complete within seconds; an hour bounds replay
/// exposure while tolerating slow manual flows.
pub const MAX_CONTACT_MESSAGE_LIFETIME_SECONDS: u64 = 3_600;

/// Limits for NFC/BLE contact delivery framing.
///
/// These are intentionally conservative defaults.
#[derive(Debug, Clone)]
pub struct ContactLimits {
    /// Max bytes for a full reassembled message (CBOR bytes).
    pub max_message_bytes: usize,

    /// Max bytes per frame (CBOR bytes).
    pub max_frame_bytes: usize,

    /// Max number of frames allowed per message.
    pub max_frames: usize,

    /// Session ID byte length.
    pub session_id_len: usize,
}

impl Default for ContactLimits {
    fn default() -> Self {
        Self {
            // 64 KiB is a reasonable ceiling for contact payloads; higher-level
            // signed payloads (mdoc/OpenID4VP) should stay well below this.
            max_message_bytes: MAX_CONTACT_MESSAGE_CBOR_BYTES,

            // Typical BLE ATT payloads are much smaller, but this is the CBOR
            // envelope size. Apps can set lower values for real transports.
            max_frame_bytes: 1_024,

            // 64 KiB / 512B ~ 128 frames; allow some headroom.
            max_frames: 256,

            // 128-bit session IDs.
            session_id_len: CONTACT_SESSION_ID_BYTES,
        }
    }
}

impl ContactLimits {
    /// Validate caller-selected limits against the codec's absolute ceilings.
    ///
    /// Applications may lower transport limits, but accepting larger values
    /// would let an untrusted transport override the allocation policy owned by
    /// this crate.
    pub fn validate(&self) -> Result<(), ContactDeliveryError> {
        if self.max_message_bytes == 0
            || self.max_message_bytes > MAX_CONTACT_MESSAGE_CBOR_BYTES
            || self.max_frame_bytes == 0
            || self.max_frame_bytes > MAX_CONTACT_FRAME_CBOR_BYTES
            || self.max_frames == 0
            || self.max_frames > MAX_CONTACT_FRAMES
            || self.session_id_len != CONTACT_SESSION_ID_BYTES
        {
            return Err(ContactDeliveryError::InvalidInput);
        }

        Ok(())
    }
}
