// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use identity_presentation_delivery_contact_core::{
    decode_contact_message_cbor, reassemble_frames, sha256_bytes, ContactLimits, ContactMessage,
};

use crate::ContactValidationError;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Successfully validated contact message and its decoded envelope.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct VerifiedContactMessage {
    /// Decoded contact message whose envelope checks have passed.
    pub message: ContactMessage,
}

impl core::fmt::Debug for VerifiedContactMessage {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("VerifiedContactMessage")
            .field("contents", &"<redacted>")
            .finish()
    }
}

/// Validate a full contact message (CBOR bytes).
pub fn validate_contact_message_cbor(
    message_cbor: &[u8],
    expected_session_transcript_cbor: &[u8],
    now_unix: u64,
    limits: &ContactLimits,
) -> Result<VerifiedContactMessage, ContactValidationError> {
    limits
        .validate()
        .map_err(|_| ContactValidationError::InvalidInput)?;
    if message_cbor.len() > limits.max_message_bytes {
        return Err(ContactValidationError::InvalidInput);
    }

    let msg = decode_contact_message_cbor(message_cbor)
        .map_err(|_| ContactValidationError::Serialization)?;

    if msg.version != "1.0" {
        return Err(ContactValidationError::InvalidInput);
    }
    if msg.session_id.len() != limits.session_id_len {
        return Err(ContactValidationError::InvalidInput);
    }
    if msg.session_transcript_sha256.len() != 32 {
        return Err(ContactValidationError::InvalidInput);
    }
    if msg.payload.len() > limits.max_message_bytes {
        return Err(ContactValidationError::InvalidInput);
    }

    let expected_hash = sha256_bytes(expected_session_transcript_cbor);
    if msg.session_transcript_sha256 != expected_hash.to_vec() {
        return Err(ContactValidationError::SessionTranscriptMismatch);
    }

    if now_unix > msg.expires_at {
        return Err(ContactValidationError::Expired);
    }
    if msg.created_at > now_unix {
        return Err(ContactValidationError::InvalidInput);
    }

    Ok(VerifiedContactMessage { message: msg })
}

/// Reassemble frames, then validate the resulting message CBOR.
pub fn validate_contact_frames_cbor(
    frames_cbor: &[Vec<u8>],
    expected_session_transcript_cbor: &[u8],
    now_unix: u64,
    limits: &ContactLimits,
) -> Result<VerifiedContactMessage, ContactValidationError> {
    let message_cbor =
        reassemble_frames(frames_cbor, limits).map_err(|_| ContactValidationError::InvalidInput)?;

    validate_contact_message_cbor(
        &message_cbor,
        expected_session_transcript_cbor,
        now_unix,
        limits,
    )
}
