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

use identity_presentation_delivery_siop_core::{
    build_siop_authentication_request, validate_siop_authentication_request,
    BuildSiopAuthenticationRequestInput, SiopDeliveryError, MAX_SIOP_REQUEST_LIFETIME_SECONDS,
    MAX_SIOP_SCOPES, MAX_SIOP_SCOPE_BYTES, MAX_SIOP_TEXT_BYTES,
};
use zeroize::Zeroize;

fn valid_input() -> BuildSiopAuthenticationRequestInput {
    BuildSiopAuthenticationRequestInput {
        client_id: "did:example:rp".into(),
        nonce: vec![7u8; 32],
        audience: "https://rp.example".into(),
        response_mode: "direct_post".into(),
        scope: vec!["openid".into()],
        now_unix: 100,
        ttl_secs: 60,
    }
}

#[test]
fn builds_and_validates_request() {
    let req = build_siop_authentication_request(valid_input()).unwrap();

    validate_siop_authentication_request(&req, 120).unwrap();
}

#[test]
fn rejects_wrong_nonce_len() {
    let mut input = valid_input();
    input.nonce.pop();
    let err = build_siop_authentication_request(input).unwrap_err();

    assert_eq!(err, SiopDeliveryError::InvalidInput);
}

#[test]
fn rejects_oversized_duplicate_and_excessive_request_fields() {
    let mut oversized_client = valid_input();
    oversized_client.client_id = "x".repeat(MAX_SIOP_TEXT_BYTES + 1);
    assert_eq!(
        build_siop_authentication_request(oversized_client).unwrap_err(),
        SiopDeliveryError::InvalidInput
    );

    let mut oversized_scope = valid_input();
    oversized_scope.scope = vec!["x".repeat(MAX_SIOP_SCOPE_BYTES + 1)];
    assert_eq!(
        build_siop_authentication_request(oversized_scope).unwrap_err(),
        SiopDeliveryError::InvalidInput
    );

    let mut duplicate_scope = valid_input();
    duplicate_scope.scope = vec!["openid".into(), "openid".into()];
    assert_eq!(
        build_siop_authentication_request(duplicate_scope).unwrap_err(),
        SiopDeliveryError::InvalidInput
    );

    let mut excessive_scope = valid_input();
    excessive_scope.scope = (0..=MAX_SIOP_SCOPES)
        .map(|index| index.to_string())
        .collect();
    assert_eq!(
        build_siop_authentication_request(excessive_scope).unwrap_err(),
        SiopDeliveryError::InvalidInput
    );

    let mut excessive_lifetime = valid_input();
    excessive_lifetime.ttl_secs = MAX_SIOP_REQUEST_LIFETIME_SECONDS + 1;
    assert_eq!(
        build_siop_authentication_request(excessive_lifetime).unwrap_err(),
        SiopDeliveryError::InvalidInput
    );
}

#[test]
fn request_owner_redacts_and_zeroizes_identifying_material() {
    let mut request = build_siop_authentication_request(valid_input()).unwrap();
    let diagnostic = format!("{request:?}");
    assert!(diagnostic.contains("<redacted>"));
    assert!(!diagnostic.contains("did:example:rp"));

    request.zeroize();
    assert!(request.client_id.is_empty());
    assert!(request.nonce.is_empty());
    assert!(request.audience.is_empty());
    assert!(request.scope.is_empty());
}
