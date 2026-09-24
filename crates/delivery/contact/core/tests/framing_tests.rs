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
    decode_contact_frame_cbor, decode_contact_message_cbor, encode_contact_frame_cbor,
    encode_contact_message_cbor, fragment_message, reassemble_frames, ContactDeliveryError,
    ContactFrame, ContactLimits, ContactMessage, ContactPayloadKind, MAX_CONTACT_FRAME_CBOR_BYTES,
    MAX_CONTACT_MESSAGE_CBOR_BYTES,
};

#[test]
fn fragments_and_reassembles_roundtrip() {
    let limits = ContactLimits {
        max_message_bytes: 64 * 1024,
        max_frame_bytes: 256,
        max_frames: 512,
        session_id_len: 16,
    };

    let session_id = [7u8; 16];
    let message_id = 123;

    let msg: Vec<u8> = (0..4096u32).flat_map(|i| i.to_le_bytes()).collect();

    let frames = fragment_message(&session_id, message_id, &msg, &limits).unwrap();
    assert!(frames.len() > 1);

    let rebuilt = reassemble_frames(&frames, &limits).unwrap();
    assert_eq!(rebuilt, msg);
}

#[test]
fn rejects_missing_frames() {
    let limits = ContactLimits::default();
    let session_id = [1u8; 16];
    let msg = vec![9u8; 2000];

    let frames = fragment_message(&session_id, 1, &msg, &limits).unwrap();
    let mut dropped = frames.clone();
    dropped.pop();

    assert!(reassemble_frames(&dropped, &limits).is_err());
}

#[test]
fn empty_frame_fits_in_256_bytes() {
    let session_id = vec![1u8; 16];
    let f = ContactFrame {
        version: "1.0".into(),
        session_id,
        message_id: 1,
        seq: 0,
        total: 1,
        chunk: vec![],
    };

    let b = encode_contact_frame_cbor(&f).unwrap();
    assert!(b.len() <= 256);
}

#[test]
fn codec_rejects_oversized_inputs_before_decoding() {
    let message = vec![0u8; MAX_CONTACT_MESSAGE_CBOR_BYTES + 1];
    assert!(matches!(
        decode_contact_message_cbor(&message),
        Err(ContactDeliveryError::MessageTooLarge)
    ));

    let frame = vec![0u8; MAX_CONTACT_FRAME_CBOR_BYTES + 1];
    assert!(matches!(
        decode_contact_frame_cbor(&frame),
        Err(ContactDeliveryError::FrameTooLarge)
    ));
}

#[test]
fn codec_rejects_models_that_exceed_owned_memory_policy() {
    let message = ContactMessage {
        version: "1.0".into(),
        kind: ContactPayloadKind::Request,
        session_id: vec![1u8; 16],
        session_transcript_sha256: vec![2u8; 32],
        message_id: 1,
        content_type: Some("application/cbor".into()),
        created_at: 1,
        expires_at: 2,
        payload: vec![0u8; MAX_CONTACT_MESSAGE_CBOR_BYTES],
    };
    assert!(matches!(
        encode_contact_message_cbor(&message),
        Err(ContactDeliveryError::MessageTooLarge)
    ));

    let invalid_limits = ContactLimits {
        max_message_bytes: MAX_CONTACT_MESSAGE_CBOR_BYTES + 1,
        ..ContactLimits::default()
    };
    assert!(matches!(
        fragment_message(&[0u8; 16], 1, &[], &invalid_limits),
        Err(ContactDeliveryError::InvalidInput)
    ));
}
