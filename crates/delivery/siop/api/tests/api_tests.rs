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

use identity_presentation_delivery_siop_api::{
    build_siop_authentication_request, validate_siop_authentication_request,
    verify_siop_authentication_response, BuildSiopAuthenticationRequestInput,
};
use identity_presentation_delivery_siop_verifier::SiopKeyResolver;

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
fn api_builds_and_verifies_flow() {
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
    let resolver = StaticResolver {
        jwk: jwk.clone(),
        pk,
    };

    let req = build_siop_authentication_request(BuildSiopAuthenticationRequestInput {
        client_id: "did:example:rp".into(),
        nonce: vec![1u8; 32],
        audience: "https://rp.example".into(),
        response_mode: "direct_post".into(),
        scope: vec!["openid".into()],
        now_unix: 100,
        ttl_secs: 60,
    })
    .unwrap();

    validate_siop_authentication_request(&req, 120).unwrap();

    let nonce_b64url = codec_base64url::bytes_to_base64url(&req.nonce);

    let claims = identity_presentation_delivery_siop_core::SiopIdTokenClaims {
        iss: "did:example:holder".into(),
        sub: "did:example:holder".into(),
        aud: vec![req.audience.clone()],
        nonce: nonce_b64url,
        iat: 100,
        exp: 200,
    };

    let jwt = encode_signed_jwt(&claims, &jwk, &sk).unwrap();
    let verified = verify_siop_authentication_response(&req, &jwt, &resolver, 120).unwrap();
    assert_eq!(verified.claims.iss, "did:example:holder");
}
