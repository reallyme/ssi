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
        // Compact-JWS-shaped test token; the signature segment is not verified here.
        Ok(format!(
            "eyJhbGciOiJFZERTQSJ9.{}.c2lnbmF0dXJl",
            codec_base64url::bytes_to_base64url(payload_json)
        ))
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

struct FixedJwtSigner(&'static str);

impl GoogleWalletJwtSigner for FixedJwtSigner {
    fn sign_jwt(&self, _payload_json: &[u8]) -> Result<String, WebDeliveryError> {
        Ok(self.0.to_owned())
    }
}

#[test]
fn deep_link_accepts_wallet_invocation_schemes() {
    let limits = WebLimits::default();
    for base in [
        "openid4vp://authorize",
        "haip://",
        "openid-credential-offer://",
        "eudi-openid4vp://",
    ] {
        build_deep_link(base, &[("request_uri", "https://rp.example/r/1")], &limits)
            .unwrap_or_else(|_| panic!("{base} must be accepted"));
    }
}

#[test]
fn deep_link_rejects_disallowed_schemes_and_userinfo() {
    let limits = WebLimits::default();
    for base in [
        "javascript:alert(1)",
        "data:text/html,hi",
        "http://wallet.example/import",
        "file:///etc/passwd",
        "intent://scan#Intent;end",
        "https://user:secret@wallet.example/import",
        "openid4vp://user@authorize",
    ] {
        let err = build_deep_link(base, &[("payload", "abc")], &limits).unwrap_err();
        assert_eq!(err, WebDeliveryError::InvalidUrl, "{base}");
    }
}

#[test]
fn deep_link_rejects_oversized_inputs_before_parsing() {
    let limits = WebLimits::default();
    let oversized_base = format!(
        "https://wallet.example/{}",
        "a".repeat(limits.max_url_bytes)
    );
    let err = build_deep_link(&oversized_base, &[], &limits).unwrap_err();
    assert_eq!(
        err,
        WebDeliveryError::Delivery(DeliveryError::PayloadTooLarge)
    );

    let oversized_value = "v".repeat(limits.max_url_bytes);
    let err = build_deep_link(
        "https://wallet.example/import",
        &[("payload", oversized_value.as_str())],
        &limits,
    )
    .unwrap_err();
    assert_eq!(
        err,
        WebDeliveryError::Delivery(DeliveryError::PayloadTooLarge)
    );
}

#[test]
fn google_wallet_save_link_rejects_non_https_or_ambiguous_prefix() {
    let limits = WebLimits::default();
    let payload = DeliveryPayload::Text(r#"{"id":"issuer/object"}"#.into());
    for prefix in [
        "http://pay.google.com/gp/v/save/",
        "https://pay.google.com/gp/v/save",
        "https://user@pay.google.com/gp/v/save/",
        "https://pay.google.com/gp/v/save/?x=",
        "javascript:alert(1)//",
    ] {
        let cfg = GoogleWalletSaveConfig {
            save_url_prefix: prefix.into(),
        };
        let err =
            build_google_wallet_save_link(&payload, &DummyJwtSigner, &cfg, &limits).unwrap_err();
        assert_eq!(err, WebDeliveryError::InvalidUrl, "{prefix}");
    }
}

#[test]
fn google_wallet_save_link_rejects_malformed_signer_output() {
    let limits = WebLimits::default();
    let cfg = GoogleWalletSaveConfig::default();
    let payload = DeliveryPayload::Text(r#"{"id":"issuer/object"}"#.into());
    for token in [
        "only-one-segment",
        "a.b",
        "a.b.c.d",
        "a..c",
        "a.b.c?redirect=https://evil.example",
        "a.b.c#fragment",
        "a.b/../c.d",
        "a.b.c=",
    ] {
        let err = build_google_wallet_save_link(&payload, &FixedJwtSigner(token), &cfg, &limits)
            .unwrap_err();
        assert_eq!(err, WebDeliveryError::SigningFailed, "{token}");
    }
}
