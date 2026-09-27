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
    verify_siop_authentication_response, SiopKeyResolver, SiopVerifierError,
    MAX_SIOP_ID_TOKEN_BYTES,
};

struct StaticResolver {
    jwk: Jwk,
    pk: Vec<u8>,
}

struct ExactKidResolver {
    expected_kid: &'static str,
    jwk: Jwk,
    pk: Vec<u8>,
}

struct NonAuthenticationResolver {
    jwk: Jwk,
    pk: Vec<u8>,
}

impl SiopKeyResolver for NonAuthenticationResolver {
    fn resolve(&self, _kid: Option<&str>) -> Option<(Jwk, Vec<u8>)> {
        Some((self.jwk.clone(), self.pk.clone()))
    }

    fn is_authentication_method(&self, _subject_did: &str, _kid: &str) -> bool {
        false
    }
}

impl SiopKeyResolver for ExactKidResolver {
    fn resolve(&self, kid: Option<&str>) -> Option<(Jwk, Vec<u8>)> {
        (kid == Some(self.expected_kid)).then(|| (self.jwk.clone(), self.pk.clone()))
    }

    fn is_authentication_method(&self, subject_did: &str, kid: &str) -> bool {
        subject_did == HOLDER_DID && kid == self.expected_kid
    }
}

impl SiopKeyResolver for StaticResolver {
    fn resolve(&self, _kid: Option<&str>) -> Option<(Jwk, Vec<u8>)> {
        Some((self.jwk.clone(), self.pk.clone()))
    }

    fn is_authentication_method(&self, subject_did: &str, kid: &str) -> bool {
        subject_did == HOLDER_DID && kid == HOLDER_KID
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
        state: "state-1234567890abcdef".into(),
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
        azp: None,
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

fn response(jwt: &str, state: &str) -> SiopAuthenticationResponse {
    SiopAuthenticationResponse {
        id_token: jwt.as_bytes().to_vec(),
        state: state.to_owned(),
    }
}

#[test]
fn verifies_id_token_against_request() {
    let req = request();
    let (jwt, resolver) = signed_did_token(&did_claims(&req), HOLDER_KID);

    verify_siop_authentication_response(&req, &response(&jwt, &req.state), &resolver, 120).unwrap();
}

#[test]
fn rejects_valid_signature_from_key_outside_authentication_relationship() {
    let req = request();
    let (jwt, resolver) = signed_did_token(&did_claims(&req), HOLDER_KID);
    let resolver = NonAuthenticationResolver {
        jwk: resolver.jwk,
        pk: resolver.pk,
    };

    let result =
        verify_siop_authentication_response(&req, &response(&jwt, &req.state), &resolver, 120);
    assert!(matches!(result, Err(SiopVerifierError::SubjectMismatch)));
}

#[test]
fn rejects_audience_that_is_not_the_client_id() {
    let req = request();
    let mut claims = did_claims(&req);
    claims.aud = vec!["https://rp.example".into()];
    let (jwt, resolver) = signed_did_token(&claims, HOLDER_KID);

    let result =
        verify_siop_authentication_response(&req, &response(&jwt, &req.state), &resolver, 120);
    assert!(matches!(result, Err(SiopVerifierError::AudienceMismatch)));
}

#[test]
fn enforces_authorized_party_for_multiple_audiences() {
    let req = request();
    let mut claims = did_claims(&req);
    claims.aud.push("did:example:other-rp".into());

    let (jwt, resolver) = signed_did_token(&claims, HOLDER_KID);
    assert!(matches!(
        verify_siop_authentication_response(&req, &response(&jwt, &req.state), &resolver, 120,),
        Err(SiopVerifierError::AudienceMismatch)
    ));

    claims.azp = Some(req.client_id.clone());
    let (jwt, resolver) = signed_did_token(&claims, HOLDER_KID);
    verify_siop_authentication_response(&req, &response(&jwt, &req.state), &resolver, 120).unwrap();

    claims.azp = Some("did:example:other-rp".into());
    let (jwt, resolver) = signed_did_token(&claims, HOLDER_KID);
    assert!(matches!(
        verify_siop_authentication_response(&req, &response(&jwt, &req.state), &resolver, 120,),
        Err(SiopVerifierError::AudienceMismatch)
    ));
}

#[test]
fn resolver_is_queried_for_the_exact_protected_key_identifier() {
    let req = request();
    let claims = did_claims(&req);
    let (pk, sk) = generate_keypair(Algorithm::Ed25519).unwrap();
    let expected_jwk = ed25519_jwk(&pk, Some(HOLDER_KID));
    let resolver = ExactKidResolver {
        expected_kid: HOLDER_KID,
        jwk: expected_jwk,
        pk: pk.clone(),
    };

    let unknown_kid_jwk = ed25519_jwk(&pk, Some("did:example:holder#unknown"));
    let jwt = encode_signed_jwt(&claims, &unknown_kid_jwk, &sk).unwrap();
    assert!(matches!(
        verify_siop_authentication_response(&req, &response(&jwt, &req.state), &resolver, 120,),
        Err(SiopVerifierError::InvalidInput)
    ));
}

#[test]
fn rejects_a_resolver_key_whose_identifier_differs_from_the_header() {
    let req = request();
    let claims = did_claims(&req);
    let (pk, sk) = generate_keypair(Algorithm::Ed25519).unwrap();
    let header_jwk = ed25519_jwk(&pk, Some(HOLDER_KID));
    let jwt = encode_signed_jwt(&claims, &header_jwk, &sk).unwrap();
    let resolver = StaticResolver {
        jwk: ed25519_jwk(&pk, Some("did:example:holder#other-key")),
        pk,
    };

    assert!(matches!(
        verify_siop_authentication_response(&req, &response(&jwt, &req.state), &resolver, 120),
        Err(SiopVerifierError::InvalidInput)
    ));
}

#[test]
fn rejects_issuer_that_differs_from_subject() {
    let req = request();
    let mut claims = did_claims(&req);
    claims.iss = "did:example:someone-else".into();
    let (jwt, resolver) = signed_did_token(&claims, HOLDER_KID);

    let result =
        verify_siop_authentication_response(&req, &response(&jwt, &req.state), &resolver, 120);
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
        let result =
            verify_siop_authentication_response(&req, &response(&jwt, &req.state), &resolver, 120);
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
    verify_siop_authentication_response(&req, &response(&jwt, &req.state), &resolver, 120).unwrap();

    // An attacker claims the holder's thumbprint subject but signs with its own key.
    let (attacker_pk, attacker_sk) = generate_keypair(Algorithm::Ed25519).unwrap();
    let attacker_jwk = ed25519_jwk(&attacker_pk, None);
    let forged = encode_signed_jwt(&claims, &attacker_jwk, &attacker_sk).unwrap();
    let attacker_resolver = StaticResolver {
        jwk: attacker_jwk,
        pk: attacker_pk,
    };
    let result = verify_siop_authentication_response(
        &req,
        &response(&forged, &req.state),
        &attacker_resolver,
        120,
    );
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
    let result =
        verify_siop_authentication_response(&req, &response(&jwt, &req.state), &resolver, 120);
    assert!(matches!(result, Err(SiopVerifierError::SubjectMismatch)));
}

#[test]
fn enforces_response_state_binding() {
    let req = request();
    let (jwt, resolver) = signed_did_token(&did_claims(&req), HOLDER_KID);
    verify_siop_authentication_response(
        &req,
        &response(&jwt, "state-1234567890abcdef"),
        &resolver,
        120,
    )
    .unwrap();

    for received in ["state-2", ""] {
        let result =
            verify_siop_authentication_response(&req, &response(&jwt, received), &resolver, 120);
        assert!(matches!(result, Err(SiopVerifierError::StateMismatch)));
    }
}

#[test]
fn revalidates_the_originating_request() {
    let req = request();
    let (jwt, resolver) = signed_did_token(&did_claims(&req), HOLDER_KID);

    // Verifier time before the request was created.
    let result =
        verify_siop_authentication_response(&req, &response(&jwt, &req.state), &resolver, 99);
    assert!(matches!(result, Err(SiopVerifierError::InvalidInput)));

    let result =
        verify_siop_authentication_response(&req, &response(&jwt, &req.state), &resolver, 160);
    assert!(matches!(result, Err(SiopVerifierError::Expired)));
}

#[test]
fn rejects_oversized_token_before_key_resolution() {
    let req = request();
    let resolver = RejectingResolver;
    let token = "a".repeat(MAX_SIOP_ID_TOKEN_BYTES + 1);
    let result =
        verify_siop_authentication_response(&req, &response(&token, &req.state), &resolver, 120);
    assert!(matches!(result, Err(SiopVerifierError::InvalidInput)));
}

#[test]
fn rejects_invalid_claim_time_window_after_signature_verification() {
    let req = request();
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
    let claims = SiopIdTokenClaims {
        iss: "did:example:holder".into(),
        sub: "did:example:holder".into(),
        aud: vec![req.client_id.clone()],
        azp: None,
        nonce: codec_base64url::bytes_to_base64url(&req.nonce),
        iat: 120,
        exp: 120,
        sub_jwk: None,
    };
    let jwt = encode_signed_jwt(&claims, &jwk, &sk).unwrap();
    let resolver = StaticResolver { jwk, pk };

    let result =
        verify_siop_authentication_response(&req, &response(&jwt, &req.state), &resolver, 120);
    assert!(matches!(result, Err(SiopVerifierError::InvalidInput)));
}

struct RejectingResolver;

impl SiopKeyResolver for RejectingResolver {
    fn resolve(&self, _kid: Option<&str>) -> Option<(Jwk, Vec<u8>)> {
        panic!("oversized input must be rejected before key resolution")
    }

    fn is_authentication_method(&self, _subject_did: &str, _kid: &str) -> bool {
        panic!("oversized input must be rejected before relationship resolution")
    }
}
