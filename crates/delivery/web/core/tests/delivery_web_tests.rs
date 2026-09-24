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
//! Tests for web delivery payload, QR, and link helpers.

use identity_presentation_delivery_core::{
    DeliveryEnvelope, DeliveryError, DeliveryIntent, DeliveryPayload, DeliveryTarget,
};
use identity_presentation_delivery_web_core::{
    build_deep_link, build_google_wallet_save_link, build_qr_payload, GoogleWalletJwtSigner,
    GoogleWalletSaveConfig, QrPayload, WebDeliveryError, WebLimits,
};

struct DummyJwtSigner;

impl GoogleWalletJwtSigner for DummyJwtSigner {
    fn sign_jwt(&self, payload_json: &[u8]) -> Result<String, WebDeliveryError> {
        // Fake JWT: base64url(payload)
        Ok(codec_base64url::bytes_to_base64url(payload_json))
    }
}

#[test]
fn qr_payload_from_text() {
    let env = DeliveryEnvelope {
        payload: DeliveryPayload::Text("hello".into()),
        intent: DeliveryIntent::Present,
        target: DeliveryTarget::Web,
        expires_at: Some(1_800_000_000),
    };

    let out = build_qr_payload(&env, 1_700_000_000, &WebLimits::default()).unwrap();
    assert!(matches!(out, QrPayload::Text(_)));
}

#[test]
fn qr_payload_from_bytes_is_base64url() {
    let env = DeliveryEnvelope {
        payload: DeliveryPayload::Bytes(vec![1, 2, 3]),
        intent: DeliveryIntent::Present,
        target: DeliveryTarget::Web,
        expires_at: None,
    };

    let out = build_qr_payload(&env, 1_700_000_000, &WebLimits::default()).unwrap();
    match &out {
        QrPayload::Text(s) => {
            let b = codec_base64url::base64url_to_bytes(s).unwrap();
            assert_eq!(b, vec![1, 2, 3]);
        }
        _ => panic!("expected text"),
    }
}

#[test]
fn deep_link_builds_url() {
    let limits = WebLimits::default();
    let url = build_deep_link(
        "https://example.com/import",
        &[("payload", "abc"), ("x", "1")],
        &limits,
    )
    .unwrap();

    assert!(url.starts_with("https://example.com/import?"));
    assert!(url.contains("payload=abc"));
}

#[test]
fn google_wallet_save_link_builds() {
    let limits = WebLimits::default();
    let cfg = GoogleWalletSaveConfig::default();

    let payload = DeliveryPayload::Text(r#"{"id":"issuer/object"}"#.into());
    let url = build_google_wallet_save_link(&payload, &DummyJwtSigner, &cfg, &limits).unwrap();

    assert!(url
        .as_str()
        .starts_with("https://pay.google.com/gp/v/save/"));
}

#[test]
fn expired_envelope_fails() {
    let env = DeliveryEnvelope {
        payload: DeliveryPayload::Text("x".into()),
        intent: DeliveryIntent::Present,
        target: DeliveryTarget::Web,
        expires_at: Some(1_600_000_000),
    };

    let err = build_qr_payload(&env, 1_700_000_000, &WebLimits::default()).unwrap_err();
    assert!(matches!(
        err,
        WebDeliveryError::Delivery(DeliveryError::Expired)
    ));
}
