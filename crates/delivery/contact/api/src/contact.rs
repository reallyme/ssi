// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::print_stdout,
        clippy::print_stderr
    )
)]
//! Public contact delivery API over the core framing and validator crates.
//!
//! This crate provides a typed boundary for SDK and wallet layers.
//! It composes deterministic message construction, frame fragmentation, and
//! validation without owning any platform NFC/BLE I/O.

#[path = "error.rs"]
mod error;

pub use error::ContactApiError;

use identity_presentation_delivery_contact_core::{
    derive_contact_message_id, derive_contact_session_id, encode_contact_message_cbor,
    fragment_message, sha256_bytes, ContactLimits, ContactMessage, ContactPayloadKind,
    MAX_CONTACT_MESSAGE_LIFETIME_SECONDS,
};
use identity_presentation_delivery_contact_validator::{
    validate_contact_frames_cbor, validate_contact_message_cbor, ValidatedContactEnvelope,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Inputs required to build a contact delivery message.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct BuildContactMessageInput {
    /// Protocol role of the embedded payload.
    pub kind: ContactPayloadKind,

    /// Optional media type or protocol-specific payload hint.
    pub content_type: Option<String>,

    /// CBOR session transcript bytes used for replay-resistant binding.
    pub session_transcript_cbor: Vec<u8>,

    /// Message creation time in Unix seconds.
    pub now_unix: u64,

    /// Message lifetime in seconds.
    pub ttl_secs: u64,

    /// Opaque protocol payload carried by the contact message.
    pub payload: Vec<u8>,
}

/// Result of constructing a contact message before fragmentation.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct BuiltContactMessage {
    /// Derived session identifier shared by all frames for this message.
    pub session_id: Vec<u8>,

    /// Deterministic message identifier derived from transcript, payload, and kind.
    pub message_id: u32,

    /// CBOR-encoded contact message ready for frame fragmentation.
    pub message_cbor: Vec<u8>,
}

impl core::fmt::Debug for BuildContactMessageInput {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("BuildContactMessageInput")
            .field("contents", &"<redacted>")
            .finish()
    }
}

impl core::fmt::Debug for BuiltContactMessage {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("BuiltContactMessage")
            .field("contents", &"<redacted>")
            .finish()
    }
}

/// Build a contact message (CBOR) and deterministic identifiers.
///
/// - `session_id` is derived from `sha256(session_transcript_cbor)[0..16]`
/// - `message_id` is derived from `sha256(session_transcript_cbor || payload || kind_string)[0..4]`
/// - `ttl_secs` must not exceed `MAX_CONTACT_MESSAGE_LIFETIME_SECONDS`
pub fn build_contact_message_cbor(
    mut input: BuildContactMessageInput,
    limits: &ContactLimits,
) -> Result<BuiltContactMessage, ContactApiError> {
    if input.payload.len() > limits.max_message_bytes {
        return Err(ContactApiError::InvalidInput);
    }
    if input.ttl_secs == 0 || input.ttl_secs > MAX_CONTACT_MESSAGE_LIFETIME_SECONDS {
        return Err(ContactApiError::InvalidInput);
    }
    limits
        .validate()
        .map_err(|_| ContactApiError::InvalidInput)?;

    let transcript_hash = sha256_bytes(&input.session_transcript_cbor);
    let session_id = derive_contact_session_id(&input.session_transcript_cbor).to_vec();
    let message_id =
        derive_contact_message_id(&input.session_transcript_cbor, &input.payload, input.kind)?;

    let msg = ContactMessage {
        version: "1.0".into(),
        kind: input.kind,
        session_id: session_id.clone(),
        session_transcript_sha256: transcript_hash.to_vec(),
        message_id,
        content_type: core::mem::take(&mut input.content_type),
        created_at: input.now_unix,
        expires_at: input
            .now_unix
            .checked_add(input.ttl_secs)
            .ok_or(ContactApiError::InvalidInput)?,
        payload: core::mem::take(&mut input.payload),
    };

    let message_cbor = encode_contact_message_cbor(&msg)?;
    if message_cbor.len() > limits.max_message_bytes {
        return Err(ContactApiError::InvalidInput);
    }

    Ok(BuiltContactMessage {
        session_id,
        message_id,
        message_cbor,
    })
}

/// Fragment an already-built contact message CBOR into CBOR-encoded frames.
pub fn build_contact_frames_cbor(
    session_id: &[u8],
    message_id: u32,
    message_cbor: &[u8],
    limits: &ContactLimits,
) -> Result<Vec<Vec<u8>>, ContactApiError> {
    Ok(fragment_message(
        session_id,
        message_id,
        message_cbor,
        limits,
    )?)
}

/// Validate a contact message CBOR.
pub fn validate_contact_message(
    message_cbor: &[u8],
    expected_session_transcript_cbor: &[u8],
    now_unix: u64,
    limits: &ContactLimits,
) -> Result<ValidatedContactEnvelope, ContactApiError> {
    Ok(validate_contact_message_cbor(
        message_cbor,
        expected_session_transcript_cbor,
        now_unix,
        limits,
    )?)
}

/// Validate contact frames (reassemble + validate).
pub fn validate_contact_frames(
    frames_cbor: &[Vec<u8>],
    expected_session_transcript_cbor: &[u8],
    now_unix: u64,
    limits: &ContactLimits,
) -> Result<ValidatedContactEnvelope, ContactApiError> {
    Ok(validate_contact_frames_cbor(
        frames_cbor,
        expected_session_transcript_cbor,
        now_unix,
        limits,
    )?)
}
