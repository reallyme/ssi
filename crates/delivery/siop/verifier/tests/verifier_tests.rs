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

use crypto_core::Algorithm;
use crypto_dispatch::generate_keypair;
use envelopes_jwk::Jwk;
use envelopes_jwt::jwt::encode_signed_jwt;

use identity_presentation_delivery_siop_core::{
    build_siop_authentication_request, BuildSiopAuthenticationRequestInput, SiopIdTokenClaims,
};
use identity_presentation_delivery_siop_verifier::{
    verify_siop_authentication_response, verify_siop_id_token_jwt, SiopKeyResolver,
    SiopVerifierError, MAX_SIOP_ID_TOKEN_BYTES,
};

struct StaticResolver {
    jwk: Jwk,
    pk: Vec<u8>,
}

impl SiopKeyResolver for StaticResolver {
    fn resolve(&self, _kid: Option<&str>) -> Option<(Jwk, Vec<u8>)> {
        Some((self.jwk.clone(), self.pk.clone()))
    }
}

#[test]
fn verifies_id_token_against_request() {
    let (pk, sk) = generate_keypair(Algorithm::Ed25519).unwrap();
    let ed_jwk = envelopes_jwk::ed25519_public_key_to_jwk(
        &pk,
        envelopes_jwk::JwkOptions {
            alg: true,
            use_sig: true,
            kid: Some("kid1".into()),
            ..Default::default()
        },
    )
    .unwrap();
    let jwk = Jwk::Okp(envelopes_jwk::OkpJwk::from(ed_jwk));

    let req = build_siop_authentication_request(BuildSiopAuthenticationRequestInput {
        client_id: "did:example:rp".into(),
        nonce: vec![7u8; 32],
        audience: "https://rp.example".into(),
        response_mode: "direct_post".into(),
        scope: vec!["openid".into()],
        now_unix: 100,
        ttl_secs: 60,
    })
    .unwrap();

    let nonce_b64url = codec_base64url::bytes_to_base64url(&req.nonce);

    let claims = SiopIdTokenClaims {
        iss: "did:example:holder".into(),
        sub: "did:example:holder".into(),
        aud: vec![req.audience.clone()],
        nonce: nonce_b64url,
        iat: 100,
        exp: 200,
    };

    let jwt = encode_signed_jwt(&claims, &jwk, &sk).unwrap();
    let resolver = StaticResolver { jwk, pk };

    verify_siop_authentication_response(&req, &jwt, &resolver, 120).unwrap();
}

#[test]
fn rejects_oversized_token_before_key_resolution() {
    let resolver = RejectingResolver;
    let token = "a".repeat(MAX_SIOP_ID_TOKEN_BYTES + 1);
    let result = verify_siop_id_token_jwt(
        &token,
        &resolver,
        "https://rp.example",
        "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc",
        120,
    );
    assert!(matches!(result, Err(SiopVerifierError::InvalidInput)));
}

#[test]
fn rejects_invalid_claim_time_window_after_signature_verification() {
    let (pk, sk) = generate_keypair(Algorithm::Ed25519).unwrap();
    let ed_jwk = envelopes_jwk::ed25519_public_key_to_jwk(
        &pk,
        envelopes_jwk::JwkOptions {
            alg: true,
            use_sig: true,
            kid: Some("kid1".into()),
            ..Default::default()
        },
    )
    .unwrap();
    let jwk = Jwk::Okp(envelopes_jwk::OkpJwk::from(ed_jwk));
    let nonce = "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc";
    let claims = SiopIdTokenClaims {
        iss: "did:example:holder".into(),
        sub: "did:example:holder".into(),
        aud: vec!["https://rp.example".into()],
        nonce: nonce.into(),
        iat: 200,
        exp: 200,
    };
    let jwt = encode_signed_jwt(&claims, &jwk, &sk).unwrap();
    let resolver = StaticResolver { jwk, pk };

    let result = verify_siop_id_token_jwt(&jwt, &resolver, "https://rp.example", nonce, 200);
    assert!(matches!(result, Err(SiopVerifierError::InvalidInput)));
}

struct RejectingResolver;

impl SiopKeyResolver for RejectingResolver {
    fn resolve(&self, _kid: Option<&str>) -> Option<(Jwk, Vec<u8>)> {
        panic!("oversized input must be rejected before key resolution")
    }
}
