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
    build_siop_authentication_request, BuildSiopAuthenticationRequestInput,
    SiopAuthenticationRequest, SiopAuthenticationResponse, SiopIdTokenClaims, SiopSubjectJwk,
};
use identity_presentation_delivery_siop_verifier::{
    verify_siop_authentication_response, verify_siop_authentication_response_with_state,
    verify_siop_id_token_jwt, SiopKeyResolver, SiopVerifierError, MAX_SIOP_ID_TOKEN_BYTES,
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

const HOLDER_DID: &str = "did:example:holder";
const HOLDER_KID: &str = "did:example:holder#key-1";
const RP_CLIENT_ID: &str = "did:example:rp";

fn ed25519_jwk(pk: &[u8], kid: Option<&str>) -> Jwk {
    let ed_jwk = envelopes_jwk::ed25519_public_key_to_jwk(
        pk,
        envelopes_jwk::JwkOptions {
            alg: true,
            use_sig: true,
            kid: kid.map(str::to_owned),
            ..Default::default()
        },
    )
    .unwrap();
    Jwk::Okp(envelopes_jwk::OkpJwk::from(ed_jwk))
}

fn thumbprint_subject(pk: &[u8]) -> (String, SiopSubjectJwk) {
    let x = codec_base64url::bytes_to_base64url(pk);
    let canonical = format!(r#"{{"crv":"Ed25519","kty":"OKP","x":"{x}"}}"#);
    let digest = reallyme_crypto::sha2::digest(canonical.as_bytes()).into_bytes();
    (
        codec_base64url::bytes_to_base64url(digest.as_slice()),
        SiopSubjectJwk {
            kty: "OKP".into(),
            crv: "Ed25519".into(),
            x,
            y: None,
        },
    )
}

fn request() -> SiopAuthenticationRequest {
    build_siop_authentication_request(BuildSiopAuthenticationRequestInput {
        client_id: RP_CLIENT_ID.into(),
        nonce: vec![7u8; 32],
        audience: "https://rp.example".into(),
        response_mode: "direct_post".into(),
        scope: vec!["openid".into()],
        now_unix: 100,
        ttl_secs: 60,
    })
    .unwrap()
}

fn did_claims(req: &SiopAuthenticationRequest) -> SiopIdTokenClaims {
    SiopIdTokenClaims {
        iss: HOLDER_DID.into(),
        sub: HOLDER_DID.into(),
        aud: vec![req.client_id.clone()],
        nonce: codec_base64url::bytes_to_base64url(&req.nonce),
        iat: 100,
        exp: 200,
        sub_jwk: None,
    }
}

fn signed_did_token(claims: &SiopIdTokenClaims, kid: &str) -> (String, StaticResolver) {
    let (pk, sk) = generate_keypair(Algorithm::Ed25519).unwrap();
    let jwk = ed25519_jwk(&pk, Some(kid));
    let jwt = encode_signed_jwt(claims, &jwk, &sk).unwrap();
    (jwt, StaticResolver { jwk, pk })
}

#[test]
fn verifies_id_token_against_request() {
    let req = request();
    let (jwt, resolver) = signed_did_token(&did_claims(&req), HOLDER_KID);

    verify_siop_authentication_response(&req, &jwt, &resolver, 120).unwrap();
}

#[test]
fn rejects_audience_that_is_not_the_client_id() {
    let req = request();
    let mut claims = did_claims(&req);
    claims.aud = vec![req.audience.clone()];
    let (jwt, resolver) = signed_did_token(&claims, HOLDER_KID);

    let result = verify_siop_authentication_response(&req, &jwt, &resolver, 120);
    assert!(matches!(result, Err(SiopVerifierError::AudienceMismatch)));
}

#[test]
fn rejects_issuer_that_differs_from_subject() {
    let req = request();
    let mut claims = did_claims(&req);
    claims.iss = "did:example:someone-else".into();
    let (jwt, resolver) = signed_did_token(&claims, HOLDER_KID);

    let result = verify_siop_authentication_response(&req, &jwt, &resolver, 120);
    assert!(matches!(result, Err(SiopVerifierError::SubjectMismatch)));
}

#[test]
fn rejects_did_subject_signed_by_another_did_key() {
    let req = request();
    let claims = did_claims(&req);
    for kid in [
        "did:example:attacker#key-1",
        "did:example:holder",
        "did:example:holder#",
    ] {
        let (jwt, resolver) = signed_did_token(&claims, kid);
        let result = verify_siop_authentication_response(&req, &jwt, &resolver, 120);
        assert!(
            matches!(result, Err(SiopVerifierError::SubjectMismatch)),
            "{kid}"
        );
    }
}

#[test]
fn verifies_jwk_thumbprint_subject_and_rejects_foreign_signing_key() {
    let req = request();
    let (holder_pk, holder_sk) = generate_keypair(Algorithm::Ed25519).unwrap();
    let (subject, sub_jwk) = thumbprint_subject(&holder_pk);
    let mut claims = did_claims(&req);
    claims.iss = subject.clone();
    claims.sub = subject;
    claims.sub_jwk = Some(sub_jwk);

    let holder_jwk = ed25519_jwk(&holder_pk, None);
    let jwt = encode_signed_jwt(&claims, &holder_jwk, &holder_sk).unwrap();
    let resolver = StaticResolver {
        jwk: holder_jwk,
        pk: holder_pk.clone(),
    };
    verify_siop_authentication_response(&req, &jwt, &resolver, 120).unwrap();

    // An attacker claims the holder's thumbprint subject but signs with its own key.
    let (attacker_pk, attacker_sk) = generate_keypair(Algorithm::Ed25519).unwrap();
    let attacker_jwk = ed25519_jwk(&attacker_pk, None);
    let forged = encode_signed_jwt(&claims, &attacker_jwk, &attacker_sk).unwrap();
    let attacker_resolver = StaticResolver {
        jwk: attacker_jwk,
        pk: attacker_pk,
    };
    let result = verify_siop_authentication_response(&req, &forged, &attacker_resolver, 120);
    assert!(matches!(result, Err(SiopVerifierError::SubjectMismatch)));

    // A thumbprint subject without `sub_jwk` is not bound to any key.
    let mut unbound = claims;
    unbound.sub_jwk = None;
    let holder_jwk = ed25519_jwk(&holder_pk, None);
    let jwt = encode_signed_jwt(&unbound, &holder_jwk, &holder_sk).unwrap();
    let resolver = StaticResolver {
        jwk: holder_jwk,
        pk: holder_pk,
    };
    let result = verify_siop_authentication_response(&req, &jwt, &resolver, 120);
    assert!(matches!(result, Err(SiopVerifierError::SubjectMismatch)));
}

#[test]
fn enforces_response_state_binding() {
    let req = request();
    let (jwt, resolver) = signed_did_token(&did_claims(&req), HOLDER_KID);
    let response = |state: Option<&str>| SiopAuthenticationResponse {
        id_token: jwt.as_bytes().to_vec(),
        state: state.map(str::to_owned),
    };

    verify_siop_authentication_response_with_state(
        &req,
        &response(Some("state-1")),
        Some("state-1"),
        &resolver,
        120,
    )
    .unwrap();

    for (received, expected) in [
        (Some("state-2"), Some("state-1")),
        (None, Some("state-1")),
        (Some("state-1"), None),
    ] {
        let result = verify_siop_authentication_response_with_state(
            &req,
            &response(received),
            expected,
            &resolver,
            120,
        );
        assert!(matches!(result, Err(SiopVerifierError::StateMismatch)));
    }
}

#[test]
fn revalidates_the_originating_request() {
    let req = request();
    let (jwt, resolver) = signed_did_token(&did_claims(&req), HOLDER_KID);

    // Verifier time before the request was created.
    let result = verify_siop_authentication_response(&req, &jwt, &resolver, 99);
    assert!(matches!(result, Err(SiopVerifierError::InvalidInput)));

    let result = verify_siop_authentication_response(&req, &jwt, &resolver, 160);
    assert!(matches!(result, Err(SiopVerifierError::Expired)));
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
        sub_jwk: None,
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
