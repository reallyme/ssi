// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Deterministic contact identifiers shared by builders and validators.
//!
//! Builders and validators must derive identifiers from the same transcript,
//! payload, and kind bytes; keeping the derivation here prevents the two sides
//! from drifting apart.

use crate::{sha256_bytes, sha256_concat, ContactDeliveryError, ContactPayloadKind};
use crate::{CONTACT_MESSAGE_ID_BYTES, CONTACT_SESSION_ID_BYTES};

/// Stable kind label mixed into the message identifier derivation.
#[must_use]
pub fn contact_payload_kind_label(kind: ContactPayloadKind) -> &'static str {
    match kind {
        ContactPayloadKind::Engagement => "engagement",
        ContactPayloadKind::Request => "request",
        ContactPayloadKind::Response => "response",
    }
}

/// Derive `session_id = SHA-256(session_transcript_cbor)[0..16]`.
#[must_use]
pub fn derive_contact_session_id(session_transcript_cbor: &[u8]) -> [u8; CONTACT_SESSION_ID_BYTES] {
    let transcript_hash = sha256_bytes(session_transcript_cbor);
    let mut session_id = [0_u8; CONTACT_SESSION_ID_BYTES];
    session_id.copy_from_slice(&transcript_hash[..CONTACT_SESSION_ID_BYTES]);
    session_id
}

/// Derive `message_id` as the little-endian `u32` of
/// `SHA-256(session_transcript_cbor || payload || kind_label)[0..4]`.
pub fn derive_contact_message_id(
    session_transcript_cbor: &[u8],
    payload: &[u8],
    kind: ContactPayloadKind,
) -> Result<u32, ContactDeliveryError> {
    let digest = sha256_concat(
        session_transcript_cbor,
        payload,
        contact_payload_kind_label(kind).as_bytes(),
    )?;
    let mut id_bytes = [0_u8; CONTACT_MESSAGE_ID_BYTES];
    id_bytes.copy_from_slice(&digest[..CONTACT_MESSAGE_ID_BYTES]);
    Ok(u32::from_le_bytes(id_bytes))
}
