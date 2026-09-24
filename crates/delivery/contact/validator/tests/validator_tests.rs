// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(
    missing_docs,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::print_stderr
)]
//! Test coverage for this crate.

use identity_presentation_delivery_contact_core::{
    encode_contact_message_cbor, fragment_message, sha256_bytes, ContactLimits, ContactMessage,
    ContactPayloadKind,
};
use identity_presentation_delivery_contact_validator::{
    validate_contact_frames_cbor, validate_contact_message_cbor, ContactValidationError,
};

#[test]
fn verifies_message_and_frames() {
    let limits = ContactLimits::default();

    let session_transcript_cbor = b"session-transcript-cbor";
    let transcript_hash = sha256_bytes(session_transcript_cbor);
    let session_id = transcript_hash[0..16].to_vec();

    let payload = b"hello-world".to_vec();

    let msg = ContactMessage {
        version: "1.0".into(),
        kind: ContactPayloadKind::Response,
        session_id: session_id.clone(),
        session_transcript_sha256: transcript_hash.to_vec(),
        message_id: 1,
        content_type: Some("application/cbor".into()),
        created_at: 100,
        expires_at: 200,
        payload,
    };

    let msg_cbor = encode_contact_message_cbor(&msg).unwrap();

    validate_contact_message_cbor(&msg_cbor, session_transcript_cbor, 150, &limits).unwrap();

    let frames = fragment_message(&session_id, 1, &msg_cbor, &limits).unwrap();
    validate_contact_frames_cbor(&frames, session_transcript_cbor, 150, &limits).unwrap();
}

#[test]
fn rejects_wrong_transcript() {
    let limits = ContactLimits::default();

    let session_transcript_cbor = b"session-transcript-cbor";
    let transcript_hash = sha256_bytes(session_transcript_cbor);
    let session_id = transcript_hash[0..16].to_vec();

    let msg = ContactMessage {
        version: "1.0".into(),
        kind: ContactPayloadKind::Request,
        session_id,
        session_transcript_sha256: transcript_hash.to_vec(),
        message_id: 1,
        content_type: None,
        created_at: 100,
        expires_at: 200,
        payload: vec![1, 2, 3],
    };

    let msg_cbor = encode_contact_message_cbor(&msg).unwrap();
    let err = validate_contact_message_cbor(&msg_cbor, b"wrong", 150, &limits).unwrap_err();
    assert!(matches!(
        err,
        ContactValidationError::SessionTranscriptMismatch
    ));
}
