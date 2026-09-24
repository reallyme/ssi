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
//! Tests for Google Wallet delivery helpers.

use identity_presentation_delivery_web_core::google_wallet::{
    build_generic_object, build_google_wallet_save_link, validate_google_wallet_payload,
    GoogleWalletJwtSignerImpl, GoogleWalletObject, GoogleWalletSaveConfig, Header,
};
use identity_presentation_delivery_web_core::GoogleWalletJwtSigner;

use identity_presentation_delivery_core::DeliveryPayload;
use identity_presentation_delivery_web_core::WebLimits;

use envelopes_jwt::jwt::decode_verify_jwt_signature_only;

#[path = "support.rs"]
mod support;
use support::gen_google_wallet_key;

// -----------------------------------------------------------------------------
// JWT signing & verification
// -----------------------------------------------------------------------------

#[test]
fn google_wallet_jwt_roundtrip() {
    let k = gen_google_wallet_key();

    let signer = GoogleWalletJwtSignerImpl {
        issuer: "issuer@example.com",
        jwk: &k.jwk,
        private_key: &k.private,
    };

    let payload = br#"{"id":"issuer.object","classId":"issuer.class"}"#;

    let jwt = signer.sign_jwt(payload).unwrap();

    let decoded: serde_json::Value =
        decode_verify_jwt_signature_only(&jwt, &k.jwk, &k.public).unwrap();

    assert_eq!(decoded["iss"], "issuer@example.com");
    assert_eq!(decoded["aud"], "google");
    assert_eq!(decoded["typ"], "savetowallet");
    assert_eq!(decoded["payload"]["id"], "issuer.object");
}

// -----------------------------------------------------------------------------
// Model validation
// -----------------------------------------------------------------------------

#[test]
fn validates_minimal_google_wallet_object() {
    let obj =
        build_generic_object("issuer.pass.object.1", "issuer.pass.class.1", "EU PID").unwrap();

    assert!(validate_google_wallet_payload(&obj).is_ok());
}

#[test]
fn rejects_object_with_empty_ids() {
    let obj = GoogleWalletObject {
        id: "".into(),
        class_id: "".into(),
        state: "ACTIVE".into(),
        header: Header {
            title: "Bad".into(),
            subtitle: None,
        },
        text_modules: vec![],
    };

    assert!(validate_google_wallet_payload(&obj).is_err());
}

#[test]
fn rejects_invalid_state() {
    let mut obj = build_generic_object("issuer.obj", "issuer.class", "Title").unwrap();

    obj.state = "BROKEN".into();

    assert!(validate_google_wallet_payload(&obj).is_err());
}

// -----------------------------------------------------------------------------
// Builder helpers
// -----------------------------------------------------------------------------

#[test]
fn builder_creates_active_object() {
    let obj = build_generic_object("issuer.obj", "issuer.class", "Wallet Card").unwrap();

    assert_eq!(obj.state, "ACTIVE");
    assert_eq!(obj.header.title, "Wallet Card");
}

// -----------------------------------------------------------------------------
// Save URL construction
// -----------------------------------------------------------------------------

#[test]
fn builds_google_wallet_save_url() {
    let k = gen_google_wallet_key();

    let signer = GoogleWalletJwtSignerImpl {
        issuer: "issuer@example.com",
        jwk: &k.jwk,
        private_key: &k.private,
    };

    let obj = build_generic_object("issuer.obj", "issuer.class", "EU PID").unwrap();

    validate_google_wallet_payload(&obj).unwrap();

    let json = serde_json::to_vec(&obj).unwrap();

    let url = build_google_wallet_save_link(
        &DeliveryPayload::Bytes(json),
        &signer,
        &GoogleWalletSaveConfig::default(),
        &WebLimits::default(),
    )
    .unwrap();

    assert!(url
        .as_str()
        .starts_with("https://pay.google.com/gp/v/save/"));
}

// -----------------------------------------------------------------------------
// Size limits
// -----------------------------------------------------------------------------

#[test]
fn rejects_payload_exceeding_url_limit() {
    let k = gen_google_wallet_key();

    let signer = GoogleWalletJwtSignerImpl {
        issuer: "issuer@example.com",
        jwk: &k.jwk,
        private_key: &k.private,
    };

    let huge = vec![b'a'; 10_000];

    let res = build_google_wallet_save_link(
        &DeliveryPayload::Bytes(huge),
        &signer,
        &GoogleWalletSaveConfig::default(),
        &WebLimits {
            max_url_bytes: 100,
            max_qr_bytes: 100, // required
        },
    );

    assert!(res.is_err());
}
