// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use identity_presentation_delivery_contact_core::{
    decode_contact_frame_cbor, decode_contact_message_cbor, derive_contact_message_id,
    derive_contact_session_id, reassemble_frames, sha256_bytes, ContactLimits, ContactMessage,
    MAX_CONTACT_MESSAGE_LIFETIME_SECONDS,
};

use crate::ContactValidationError;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Structurally validated contact envelope.
///
/// This type proves framing, bounds, expiry, and transcript-derived identifier
/// checks. The caller must authenticate the session transcript in its transport
/// protocol before treating the inner payload as originating from a peer.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ValidatedContactEnvelope {
    /// Decoded contact message whose envelope checks have passed.
    pub message: ContactMessage,
}

impl core::fmt::Debug for ValidatedContactEnvelope {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ValidatedContactEnvelope")
            .field("contents", &"<redacted>")
            .finish()
    }
}

/// Validate a full contact message (CBOR bytes).
///
/// Beyond decoding, this re-derives the transcript-bound `session_id` and the
/// payload-bound `message_id` and rejects messages whose identifiers, lifetime,
/// or transcript hash do not match what an honest builder would produce.
pub fn validate_contact_message_cbor(
    message_cbor: &[u8],
    expected_session_transcript_cbor: &[u8],
    now_unix: u64,
    limits: &ContactLimits,
) -> Result<ValidatedContactEnvelope, ContactValidationError> {
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

    let expected_session_id = derive_contact_session_id(expected_session_transcript_cbor);
    if msg.session_id.as_slice() != expected_session_id.as_slice() {
        return Err(ContactValidationError::SessionTranscriptMismatch);
    }
    let expected_message_id =
        derive_contact_message_id(expected_session_transcript_cbor, &msg.payload, msg.kind)
            .map_err(|_| ContactValidationError::InvalidInput)?;
    if msg.message_id != expected_message_id {
        return Err(ContactValidationError::InvalidInput);
    }

    let lifetime = msg
        .expires_at
        .checked_sub(msg.created_at)
        .ok_or(ContactValidationError::InvalidInput)?;
    if lifetime == 0 || lifetime > MAX_CONTACT_MESSAGE_LIFETIME_SECONDS {
        return Err(ContactValidationError::InvalidInput);
    }

    if now_unix > msg.expires_at {
        return Err(ContactValidationError::Expired);
    }
    if msg.created_at > now_unix {
        return Err(ContactValidationError::InvalidInput);
    }

    Ok(ValidatedContactEnvelope { message: msg })
}

/// Reassemble frames, then validate the resulting message CBOR.
pub fn validate_contact_frames_cbor(
    frames_cbor: &[Vec<u8>],
    expected_session_transcript_cbor: &[u8],
    now_unix: u64,
    limits: &ContactLimits,
) -> Result<ValidatedContactEnvelope, ContactValidationError> {
    let message_cbor =
        reassemble_frames(frames_cbor, limits).map_err(|_| ContactValidationError::InvalidInput)?;

    let verified = validate_contact_message_cbor(
        &message_cbor,
        expected_session_transcript_cbor,
        now_unix,
        limits,
    )?;

    // Reassembly guarantees every frame shares one session and message id;
    // those frame-level ids must be the ones carried by the message itself.
    let first_frame = frames_cbor
        .first()
        .ok_or(ContactValidationError::InvalidInput)?;
    let frame = decode_contact_frame_cbor(first_frame)
        .map_err(|_| ContactValidationError::Serialization)?;
    if frame.session_id != verified.message.session_id
        || frame.message_id != verified.message.message_id
    {
        return Err(ContactValidationError::InvalidInput);
    }

    Ok(verified)
}
