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
    derive_contact_message_id, derive_contact_session_id, encode_contact_message_cbor,
    fragment_message, sha256_bytes, ContactLimits, ContactMessage, ContactPayloadKind,
    MAX_CONTACT_MESSAGE_LIFETIME_SECONDS,
};
use identity_presentation_delivery_contact_validator::{
    validate_contact_frames_cbor, validate_contact_message_cbor, ContactValidationError,
};

const TRANSCRIPT: &[u8] = b"session-transcript-cbor";

fn honest_message(kind: ContactPayloadKind, payload: Vec<u8>) -> ContactMessage {
    ContactMessage {
        version: "1.0".into(),
        kind,
        session_id: derive_contact_session_id(TRANSCRIPT).to_vec(),
        session_transcript_sha256: sha256_bytes(TRANSCRIPT).to_vec(),
        message_id: derive_contact_message_id(TRANSCRIPT, &payload, kind).unwrap(),
        content_type: Some("application/cbor".into()),
        created_at: 100,
        expires_at: 200,
        payload,
    }
}

#[test]
fn verifies_message_and_frames() {
    let limits = ContactLimits::default();
    let msg = honest_message(ContactPayloadKind::Response, b"hello-world".to_vec());
    let session_id = msg.session_id.clone();
    let message_id = msg.message_id;

    let msg_cbor = encode_contact_message_cbor(&msg).unwrap();

    validate_contact_message_cbor(&msg_cbor, TRANSCRIPT, 150, &limits).unwrap();

    let frames = fragment_message(&session_id, message_id, &msg_cbor, &limits).unwrap();
    validate_contact_frames_cbor(&frames, TRANSCRIPT, 150, &limits).unwrap();
}

#[test]
fn rejects_wrong_transcript() {
    let limits = ContactLimits::default();
    let msg = honest_message(ContactPayloadKind::Request, vec![1, 2, 3]);

    let msg_cbor = encode_contact_message_cbor(&msg).unwrap();
    let err = validate_contact_message_cbor(&msg_cbor, b"wrong", 150, &limits).unwrap_err();
    assert!(matches!(
        err,
        ContactValidationError::SessionTranscriptMismatch
    ));
}

#[test]
fn rejects_session_id_not_derived_from_transcript() {
    let limits = ContactLimits::default();
    let mut msg = honest_message(ContactPayloadKind::Request, vec![1, 2, 3]);
    msg.session_id = vec![0xAA; 16];

    let msg_cbor = encode_contact_message_cbor(&msg).unwrap();
    let err = validate_contact_message_cbor(&msg_cbor, TRANSCRIPT, 150, &limits).unwrap_err();
    assert!(matches!(
        err,
        ContactValidationError::SessionTranscriptMismatch
    ));
}

#[test]
fn rejects_message_id_not_bound_to_payload_and_kind() {
    let limits = ContactLimits::default();

    let mut wrong_id = honest_message(ContactPayloadKind::Request, vec![1, 2, 3]);
    wrong_id.message_id = wrong_id.message_id.wrapping_add(1);
    let cbor = encode_contact_message_cbor(&wrong_id).unwrap();
    assert!(matches!(
        validate_contact_message_cbor(&cbor, TRANSCRIPT, 150, &limits),
        Err(ContactValidationError::InvalidInput)
    ));

    // Relabeling a request as a response changes the derived id.
    let mut relabeled = honest_message(ContactPayloadKind::Request, vec![1, 2, 3]);
    relabeled.kind = ContactPayloadKind::Response;
    let cbor = encode_contact_message_cbor(&relabeled).unwrap();
    assert!(matches!(
        validate_contact_message_cbor(&cbor, TRANSCRIPT, 150, &limits),
        Err(ContactValidationError::InvalidInput)
    ));
}

#[test]
fn rejects_inverted_or_excessive_lifetime() {
    let limits = ContactLimits::default();

    let mut inverted = honest_message(ContactPayloadKind::Response, vec![9]);
    inverted.created_at = 200;
    inverted.expires_at = 100;
    let cbor = encode_contact_message_cbor(&inverted).unwrap();
    assert!(matches!(
        validate_contact_message_cbor(&cbor, TRANSCRIPT, 150, &limits),
        Err(ContactValidationError::InvalidInput)
    ));

    let mut excessive = honest_message(ContactPayloadKind::Response, vec![9]);
    excessive.expires_at = excessive.created_at + MAX_CONTACT_MESSAGE_LIFETIME_SECONDS + 1;
    let cbor = encode_contact_message_cbor(&excessive).unwrap();
    assert!(matches!(
        validate_contact_message_cbor(&cbor, TRANSCRIPT, 150, &limits),
        Err(ContactValidationError::InvalidInput)
    ));

    let mut boundary = honest_message(ContactPayloadKind::Response, vec![9]);
    boundary.expires_at = boundary.created_at + MAX_CONTACT_MESSAGE_LIFETIME_SECONDS;
    let cbor = encode_contact_message_cbor(&boundary).unwrap();
    validate_contact_message_cbor(&cbor, TRANSCRIPT, 150, &limits).unwrap();
}

#[test]
fn rejects_frames_whose_ids_differ_from_the_message() {
    let limits = ContactLimits::default();
    let msg = honest_message(ContactPayloadKind::Response, b"hello-world".to_vec());
    let msg_cbor = encode_contact_message_cbor(&msg).unwrap();

    let frames = fragment_message(&msg.session_id, msg.message_id ^ 1, &msg_cbor, &limits).unwrap();
    assert!(matches!(
        validate_contact_frames_cbor(&frames, TRANSCRIPT, 150, &limits),
        Err(ContactValidationError::InvalidInput)
    ));

    let frames = fragment_message(&[0x55; 16], msg.message_id, &msg_cbor, &limits).unwrap();
    assert!(matches!(
        validate_contact_frames_cbor(&frames, TRANSCRIPT, 150, &limits),
        Err(ContactValidationError::InvalidInput)
    ));
}
