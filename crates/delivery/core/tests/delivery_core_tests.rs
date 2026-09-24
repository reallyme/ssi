// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::print_stderr
)]
//! Test coverage for this crate.

use identity_presentation_delivery_core::{
    DeliveryEnvelope, DeliveryIntent, DeliveryPayload, DeliveryTarget,
};
use zeroize::Zeroize;

#[test]
fn delivery_envelope_redacts_and_zeroizes_payload() {
    let mut env = DeliveryEnvelope {
        payload: DeliveryPayload::Text("hello".into()),
        intent: DeliveryIntent::Present,
        target: DeliveryTarget::Web,
        expires_at: Some(1_800_000_000),
    };

    let diagnostic = format!("{env:?}");
    assert!(diagnostic.contains("<redacted>"));
    assert!(!diagnostic.contains("hello"));

    env.zeroize();
    assert!(matches!(env.payload, DeliveryPayload::Text(ref value) if value.is_empty()));
}

#[test]
fn bytes_payload_supported() {
    let env = DeliveryEnvelope {
        payload: DeliveryPayload::Bytes(vec![1, 2, 3, 4]),
        intent: DeliveryIntent::Store,
        target: DeliveryTarget::Wallet,
        expires_at: None,
    };

    match &env.payload {
        DeliveryPayload::Bytes(b) => assert_eq!(b.len(), 4),
        _ => panic!("expected bytes payload"),
    }
}

#[test]
fn native_target_is_closed_and_typed() {
    let env = DeliveryEnvelope {
        payload: DeliveryPayload::Text("x".into()),
        intent: DeliveryIntent::Share,
        target: DeliveryTarget::Native,
        expires_at: None,
    };

    assert_eq!(env.target, DeliveryTarget::Native);
}
