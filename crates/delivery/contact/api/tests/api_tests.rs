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

use identity_presentation_delivery_contact_api::{
    build_contact_frames_cbor, build_contact_message_cbor, validate_contact_frames,
    validate_contact_message, BuildContactMessageInput, ContactApiError,
};
use identity_presentation_delivery_contact_core::{
    ContactLimits, ContactPayloadKind, MAX_CONTACT_MESSAGE_LIFETIME_SECONDS,
};

#[test]
fn builds_fragments_and_verifies() {
    let limits = ContactLimits::default();
    let now = 1000;
    let st = b"sessionTranscript".to_vec();
    let payload = vec![1, 2, 3, 4, 5];

    let built = build_contact_message_cbor(
        BuildContactMessageInput {
            kind: ContactPayloadKind::Request,
            content_type: Some("application/octet-stream".into()),
            session_transcript_cbor: st.clone(),
            now_unix: now,
            ttl_secs: 60,
            payload: payload.clone(),
        },
        &limits,
    )
    .unwrap();

    validate_contact_message(&built.message_cbor, &st, now + 1, &limits).unwrap();

    let frames = build_contact_frames_cbor(
        &built.session_id,
        built.message_id,
        &built.message_cbor,
        &limits,
    )
    .unwrap();
    let verified = validate_contact_frames(&frames, &st, now + 1, &limits).unwrap();

    assert_eq!(verified.message.payload, payload);
}

#[test]
fn rejects_lifetime_above_the_contact_maximum() {
    let limits = ContactLimits::default();
    let result = build_contact_message_cbor(
        BuildContactMessageInput {
            kind: ContactPayloadKind::Request,
            content_type: None,
            session_transcript_cbor: b"sessionTranscript".to_vec(),
            now_unix: 1000,
            ttl_secs: MAX_CONTACT_MESSAGE_LIFETIME_SECONDS + 1,
            payload: vec![1, 2, 3],
        },
        &limits,
    );
    assert!(matches!(result, Err(ContactApiError::InvalidInput)));
}
