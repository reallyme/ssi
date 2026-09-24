// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use ciborium::de::from_reader;
use ciborium::ser::into_writer;

use crate::{
    ContactDeliveryError, ContactFrame, ContactMessage, CONTACT_SESSION_ID_BYTES,
    MAX_CONTACT_FRAME_CBOR_BYTES, MAX_CONTACT_MESSAGE_CBOR_BYTES,
};

const MAX_CONTACT_VERSION_BYTES: usize = 16;
const MAX_CONTACT_CONTENT_TYPE_BYTES: usize = 256;

/// Encode a complete contact message as deterministic CBOR bytes.
pub fn encode_contact_message_cbor(msg: &ContactMessage) -> Result<Vec<u8>, ContactDeliveryError> {
    validate_message_shape(msg)?;
    let mut out = Vec::new();
    into_writer(msg, &mut out).map_err(|_| ContactDeliveryError::Serialization)?;
    if out.len() > MAX_CONTACT_MESSAGE_CBOR_BYTES {
        return Err(ContactDeliveryError::MessageTooLarge);
    }
    Ok(out)
}

/// Decode a complete contact message from CBOR bytes.
pub fn decode_contact_message_cbor(bytes: &[u8]) -> Result<ContactMessage, ContactDeliveryError> {
    if bytes.len() > MAX_CONTACT_MESSAGE_CBOR_BYTES {
        return Err(ContactDeliveryError::MessageTooLarge);
    }

    let message: ContactMessage =
        from_reader(bytes).map_err(|_| ContactDeliveryError::Serialization)?;
    validate_message_shape(&message)?;
    Ok(message)
}

/// Encode a single contact transport frame as CBOR bytes.
pub fn encode_contact_frame_cbor(frame: &ContactFrame) -> Result<Vec<u8>, ContactDeliveryError> {
    validate_frame_shape(frame)?;
    let mut out = Vec::new();
    into_writer(frame, &mut out).map_err(|_| ContactDeliveryError::Serialization)?;
    if out.len() > MAX_CONTACT_FRAME_CBOR_BYTES {
        return Err(ContactDeliveryError::FrameTooLarge);
    }
    Ok(out)
}

/// Decode a single contact transport frame from CBOR bytes.
pub fn decode_contact_frame_cbor(bytes: &[u8]) -> Result<ContactFrame, ContactDeliveryError> {
    if bytes.len() > MAX_CONTACT_FRAME_CBOR_BYTES {
        return Err(ContactDeliveryError::FrameTooLarge);
    }

    let frame: ContactFrame =
        from_reader(bytes).map_err(|_| ContactDeliveryError::Serialization)?;
    validate_frame_shape(&frame)?;
    Ok(frame)
}

fn validate_message_shape(message: &ContactMessage) -> Result<(), ContactDeliveryError> {
    if message.version.is_empty()
        || message.version.len() > MAX_CONTACT_VERSION_BYTES
        || message.session_id.len() != CONTACT_SESSION_ID_BYTES
        || message.session_transcript_sha256.len() != 32
        || message.payload.len() > MAX_CONTACT_MESSAGE_CBOR_BYTES
        || message
            .content_type
            .as_ref()
            .is_some_and(|value| value.is_empty() || value.len() > MAX_CONTACT_CONTENT_TYPE_BYTES)
    {
        return Err(ContactDeliveryError::InvalidInput);
    }

    let content_type_bytes = message.content_type.as_ref().map_or(0, String::len);
    let owned_bytes = message
        .version
        .len()
        .checked_add(message.session_id.len())
        .and_then(|size| size.checked_add(message.session_transcript_sha256.len()))
        .and_then(|size| size.checked_add(content_type_bytes))
        .and_then(|size| size.checked_add(message.payload.len()))
        .ok_or(ContactDeliveryError::MessageTooLarge)?;
    if owned_bytes > MAX_CONTACT_MESSAGE_CBOR_BYTES {
        return Err(ContactDeliveryError::MessageTooLarge);
    }

    Ok(())
}

fn validate_frame_shape(frame: &ContactFrame) -> Result<(), ContactDeliveryError> {
    if frame.version.is_empty()
        || frame.version.len() > MAX_CONTACT_VERSION_BYTES
        || frame.session_id.len() != CONTACT_SESSION_ID_BYTES
        || frame.total == 0
    {
        return Err(ContactDeliveryError::InvalidInput);
    }

    let owned_bytes = frame
        .version
        .len()
        .checked_add(frame.session_id.len())
        .and_then(|size| size.checked_add(frame.chunk.len()))
        .ok_or(ContactDeliveryError::FrameTooLarge)?;
    if owned_bytes > MAX_CONTACT_FRAME_CBOR_BYTES {
        return Err(ContactDeliveryError::FrameTooLarge);
    }

    Ok(())
}
