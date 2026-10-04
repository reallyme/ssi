// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Test coverage for this crate.

#![allow(missing_docs)]
#![allow(clippy::expect_used, clippy::unwrap_used)]

use envelopes_jwt_vc::{
    issue_jwt_vc, validate_jwt_vc_claims, verify_jwt_vc, JwtVcEnvelopeError, JwtVcIssueInput,
    JwtVcPayload, JwtVcVerificationOptions, MAX_JWT_VC_CLOCK_SKEW_SECONDS,
};
use reallyme_codec::base64url::bytes_to_base64url;
use reallyme_crypto::core::Algorithm;
use reallyme_crypto::dispatch::{generate_keypair, sign};
use reallyme_crypto::jwk::{ed25519_public_key_to_jwk, Jwk, JwkOptions};
use reallyme_jose::jwt::{encode_signed_jwt_with_header_options, JwtHeaderEncodeOptions};
use serde::Serialize;

const CANONICAL_CREDENTIAL_CBOR: &[u8] = &[0xA1, 0x61, b'a', 0x01];

struct TestKey {
    public: Vec<u8>,
    private: Vec<u8>,
    jwk: Jwk,
}

fn gen_ed25519() -> TestKey {
    let (public, private) = generate_keypair(Algorithm::Ed25519).expect("generate Ed25519 keypair");
    let jwk = ed25519_public_key_to_jwk(
        &public,
        JwkOptions {
            alg: true,
            use_sig: true,
            use_enc: false,
            kid: Some("issuer-key".to_owned()),
        },
    )
    .expect("convert Ed25519 public key to JWK");

    TestKey {
        public,
        private: private.to_vec(),
        jwk: Jwk::Okp(jwk.into()),
    }
}

fn issue_input<'a>(key: &'a TestKey) -> JwtVcIssueInput<'a> {
    JwtVcIssueInput {
        issuer: "did:me:issuer",
        subject: "did:me:subject",
        credential_cbor: CANONICAL_CREDENTIAL_CBOR,
        credential_proto: Some(b"credential-proto-bytes"),
        not_before_unix: Some(1_700_000_000),
        expires_at_unix: Some(1_800_000_000),
        jwt_id: Some("credential-1"),
        issuer_jwk: &key.jwk,
        issuer_private_key: &key.private,
    }
}

#[test]
fn issue_input_debug_redacts_private_material() {
    let key = gen_ed25519();
    let input = issue_input(&key);

    assert_eq!(format!("{input:?}"), "JwtVcIssueInput([REDACTED])");
}

fn valid_payload() -> JwtVcPayload {
    JwtVcPayload {
        iss: "did:me:issuer".to_owned(),
        sub: "did:me:subject".to_owned(),
        nbf: Some(1_700_000_000),
        exp: Some(1_800_000_000),
        iat: None,
        jti: Some("credential-1".to_owned()),
        credential_cbor: bytes_to_base64url(CANONICAL_CREDENTIAL_CBOR),
        credential_proto: None,
    }
}

fn payload_with_credential_bytes(bytes: &[u8]) -> JwtVcPayload {
    JwtVcPayload {
        iss: "did:me:issuer".to_owned(),
        sub: "did:me:subject".to_owned(),
        nbf: Some(1_700_000_000),
        exp: Some(1_800_000_000),
        iat: None,
        jti: Some("credential-1".to_owned()),
        credential_cbor: bytes_to_base64url(bytes),
        credential_proto: None,
    }
}

const NOW_UNIX: u64 = 1_750_000_000;
const CLOCK_SKEW_SECONDS: u64 = 60;

fn options_at(now_unix: u64) -> JwtVcVerificationOptions {
    JwtVcVerificationOptions {
        now_unix,
        clock_skew_seconds: CLOCK_SKEW_SECONDS,
    }
}

fn options() -> JwtVcVerificationOptions {
    options_at(NOW_UNIX)
}

fn sign_with_typ<T: Serialize>(payload: &T, key: &TestKey, typ: Option<&str>) -> String {
    encode_signed_jwt_with_header_options(
        payload,
        &key.jwk,
        &key.private,
        &JwtHeaderEncodeOptions::new(typ.map(str::to_owned)),
    )
    .expect("test JWT must sign")
}

fn sign_malformed_temporal_claims<T: Serialize>(payload: &T, key: &TestKey) -> String {
    // JOSE's normal signer rejects malformed NumericDate claims. These bytes
    // are signed directly so this negative test reaches the JWT-VC verifier
    // with an authentic signature over the malformed payload.
    let header = bytes_to_base64url(br#"{"alg":"EdDSA","kid":"issuer-key","typ":"vc+jwt"}"#);
    let payload = bytes_to_base64url(
        &serde_json::to_vec(payload).expect("malformed test payload serializes"),
    );
    let signing_input = format!("{header}.{payload}");
    let signature = sign(Algorithm::Ed25519, &key.private, signing_input.as_bytes())
        .expect("malformed test payload signs");
    format!("{signing_input}.{}", bytes_to_base64url(&signature))
}

#[test]
fn jwt_vc_issues_and_verifies_canonical_and_proto_bytes() {
    let key = gen_ed25519();
    let jwt = issue_jwt_vc(&issue_input(&key)).expect("JWT-VC must issue");
    let verified =
        verify_jwt_vc(&jwt, &key.jwk, &key.public, &options()).expect("JWT-VC must verify");

    assert_eq!(verified.payload().iss, "did:me:issuer");
    assert_eq!(verified.payload().sub, "did:me:subject");
    assert_eq!(verified.payload().jti.as_deref(), Some("credential-1"));
    assert_eq!(verified.credential_cbor(), CANONICAL_CREDENTIAL_CBOR);
    assert_eq!(
        verified.credential_proto(),
        Some(b"credential-proto-bytes".as_slice())
    );
}

#[test]
fn jwt_vc_rejects_empty_canonical_credential_bytes() {
    let key = gen_ed25519();
    let mut input = issue_input(&key);
    input.credential_cbor = b"";

    let err = issue_jwt_vc(&input).expect_err("empty credential bytes must fail");

    assert_eq!(err, JwtVcEnvelopeError::InvalidInput);
}

#[test]
fn jwt_vc_rejects_malformed_noncanonical_duplicate_and_trailing_credential_cbor() {
    let malformed = [0xff];
    let noncanonical_integer = [0xa1, 0x18, 0x01, 0x01];
    let duplicate_map_key = [0xa2, 0x61, b'a', 0x01, 0x61, b'a', 0x02];
    let trailing_data = [0xa1, 0x61, b'a', 0x01, 0x00];

    for credential in [
        malformed.as_slice(),
        noncanonical_integer.as_slice(),
        duplicate_map_key.as_slice(),
        trailing_data.as_slice(),
    ] {
        let error = validate_jwt_vc_claims(&payload_with_credential_bytes(credential))
            .expect_err("invalid canonical credential CBOR must fail");
        assert_eq!(error, JwtVcEnvelopeError::InvalidCredentialCbor);
    }
}

#[test]
fn jwt_vc_rejects_oversized_credential_before_base64url_decoding() {
    let mut payload = valid_payload();
    payload.credential_cbor = "A".repeat(1_398_105);

    let error = validate_jwt_vc_claims(&payload)
        .expect_err("encoded credential over the decoded-byte limit must fail");

    assert_eq!(error, JwtVcEnvelopeError::ResourceLimit);
}

#[test]
fn jwt_vc_rejects_empty_issuer_or_subject() {
    let key = gen_ed25519();
    let mut empty_issuer = issue_input(&key);
    empty_issuer.issuer = "";
    let issuer_err =
        issue_jwt_vc(&empty_issuer).expect_err("empty issuer must fail before signing");
    assert_eq!(issuer_err, JwtVcEnvelopeError::InvalidInput);

    let mut empty_subject = issue_input(&key);
    empty_subject.subject = "";
    let subject_err =
        issue_jwt_vc(&empty_subject).expect_err("empty subject must fail before signing");
    assert_eq!(subject_err, JwtVcEnvelopeError::InvalidInput);
}

#[test]
fn jwt_vc_rejects_empty_proto_transport_bytes() {
    let key = gen_ed25519();
    let mut input = issue_input(&key);
    input.credential_proto = Some(b"");

    let err = issue_jwt_vc(&input).expect_err("empty proto transport bytes must fail");

    assert_eq!(err, JwtVcEnvelopeError::InvalidInput);
}

#[test]
fn jwt_vc_rejects_invalid_temporal_window() {
    let payload = JwtVcPayload {
        iss: "did:me:issuer".to_owned(),
        sub: "did:me:subject".to_owned(),
        nbf: Some(10),
        exp: Some(10),
        iat: None,
        jti: None,
        credential_cbor: bytes_to_base64url(CANONICAL_CREDENTIAL_CBOR),
        credential_proto: None,
    };

    let err = validate_jwt_vc_claims(&payload).expect_err("invalid temporal window must fail");

    assert_eq!(err, JwtVcEnvelopeError::InvalidPayload);
}

#[test]
fn jwt_vc_rejects_wrong_issuer_key() {
    let key = gen_ed25519();
    let wrong = gen_ed25519();
    let jwt = issue_jwt_vc(&issue_input(&key)).expect("JWT-VC must issue");

    let err = verify_jwt_vc(&jwt, &key.jwk, &wrong.public, &options())
        .expect_err("wrong issuer public key must fail closed");

    assert_eq!(err, JwtVcEnvelopeError::Jwt);
}

#[test]
fn jwt_vc_accepts_legacy_jwt_typ_for_a_valid_profile_payload() {
    let key = gen_ed25519();
    let jwt = sign_with_typ(&valid_payload(), &key, Some("JWT"));

    let verified = verify_jwt_vc(&jwt, &key.jwk, &key.public, &options())
        .expect("legacy JWT typ must remain compatible for a valid JWT-VC payload");

    assert_eq!(verified.credential_cbor(), CANONICAL_CREDENTIAL_CBOR);
}

#[test]
fn jwt_vc_rejects_missing_and_unrelated_typ_values() {
    let key = gen_ed25519();

    for typ in [None, Some("at+jwt")] {
        let jwt = sign_with_typ(&valid_payload(), &key, typ);
        let error = verify_jwt_vc(&jwt, &key.jwk, &key.public, &options())
            .expect_err("missing or unrelated typ must fail closed");
        assert_eq!(error, JwtVcEnvelopeError::Jwt);
    }
}

#[derive(Serialize)]
struct ForeignJwtPayload<'a> {
    iss: &'a str,
    sub: &'a str,
    aud: &'a str,
}

#[test]
fn jwt_vc_rejects_a_foreign_payload_even_with_legacy_jwt_typ() {
    let key = gen_ed25519();
    let payload = ForeignJwtPayload {
        iss: "did:me:issuer",
        sub: "did:me:subject",
        aud: "https://relying-party.example",
    };
    let jwt = sign_with_typ(&payload, &key, Some("JWT"));

    let error = verify_jwt_vc(&jwt, &key.jwk, &key.public, &options())
        .expect_err("generic JWT payload must not cross the JWT-VC boundary");

    assert_eq!(error, JwtVcEnvelopeError::Jwt);
}

#[test]
fn jwt_vc_rejects_expired_credential() {
    let key = gen_ed25519();
    let jwt = issue_jwt_vc(&issue_input(&key)).expect("JWT-VC must issue");

    // `exp` is 1_800_000_000; the verifier clock sits past it by more than skew.
    let error = verify_jwt_vc(
        &jwt,
        &key.jwk,
        &key.public,
        &options_at(1_800_000_000 + CLOCK_SKEW_SECONDS),
    )
    .expect_err("expired JWT-VC must fail closed");

    assert_eq!(error, JwtVcEnvelopeError::CredentialExpired);
}

#[test]
fn jwt_vc_accepts_expiry_within_clock_skew() {
    let key = gen_ed25519();
    let jwt = issue_jwt_vc(&issue_input(&key)).expect("JWT-VC must issue");

    verify_jwt_vc(
        &jwt,
        &key.jwk,
        &key.public,
        &options_at(1_800_000_000 + CLOCK_SKEW_SECONDS - 1),
    )
    .expect("expiry inside the tolerated skew must verify");
}

#[test]
fn jwt_vc_rejects_not_yet_valid_credential() {
    let key = gen_ed25519();
    let jwt = issue_jwt_vc(&issue_input(&key)).expect("JWT-VC must issue");

    // `nbf` is 1_700_000_000; the verifier clock sits before it by more than skew.
    let error = verify_jwt_vc(
        &jwt,
        &key.jwk,
        &key.public,
        &options_at(1_700_000_000 - CLOCK_SKEW_SECONDS - 1),
    )
    .expect_err("not-yet-valid JWT-VC must fail closed");

    assert_eq!(error, JwtVcEnvelopeError::CredentialNotYetValid);
}

#[test]
fn jwt_vc_accepts_not_before_within_clock_skew() {
    let key = gen_ed25519();
    let jwt = issue_jwt_vc(&issue_input(&key)).expect("JWT-VC must issue");

    verify_jwt_vc(
        &jwt,
        &key.jwk,
        &key.public,
        &options_at(1_700_000_000 - CLOCK_SKEW_SECONDS),
    )
    .expect("not-before inside the tolerated skew must verify");
}

#[test]
fn jwt_vc_rejects_future_issued_at() {
    let key = gen_ed25519();
    let mut payload = valid_payload();
    payload.iat = Some(1_750_000_000 + 61);
    let jwt = sign_with_typ(&payload, &key, Some("vc+jwt"));

    let error = verify_jwt_vc(&jwt, &key.jwk, &key.public, &options())
        .expect_err("future iat beyond skew must fail closed");

    assert_eq!(error, JwtVcEnvelopeError::InvalidTemporalClaim);
}

#[test]
fn jwt_vc_rejects_negative_numeric_dates() {
    let key = gen_ed25519();
    let mut negative_nbf = valid_payload();
    negative_nbf.nbf = Some(-1);
    let mut negative_exp = valid_payload();
    negative_exp.nbf = None;
    negative_exp.exp = Some(-1);
    let mut negative_iat = valid_payload();
    negative_iat.iat = Some(-1);
    let cases = [negative_nbf, negative_exp, negative_iat];

    for payload in cases {
        let jwt = sign_malformed_temporal_claims(&payload, &key);
        let error = verify_jwt_vc(&jwt, &key.jwk, &key.public, &options())
            .expect_err("negative NumericDate must fail closed");
        assert_eq!(error, JwtVcEnvelopeError::InvalidTemporalClaim);
    }
}

#[derive(Serialize)]
struct NonIntegerExpPayload<'a> {
    iss: &'a str,
    sub: &'a str,
    exp: f64,
    vc_cbor: String,
}

#[test]
fn jwt_vc_rejects_non_integer_expiry() {
    let key = gen_ed25519();
    let payload = NonIntegerExpPayload {
        iss: "did:me:issuer",
        sub: "did:me:subject",
        exp: 1_800_000_000.5,
        vc_cbor: bytes_to_base64url(CANONICAL_CREDENTIAL_CBOR),
    };
    let jwt = sign_malformed_temporal_claims(&payload, &key);

    let error = verify_jwt_vc(&jwt, &key.jwk, &key.public, &options())
        .expect_err("non-integer NumericDate must fail closed");

    assert_eq!(error, JwtVcEnvelopeError::Jwt);
}

#[test]
fn jwt_vc_rejects_invalid_verification_options() {
    let key = gen_ed25519();
    let jwt = issue_jwt_vc(&issue_input(&key)).expect("JWT-VC must issue");
    let cases = [
        JwtVcVerificationOptions {
            now_unix: 0,
            clock_skew_seconds: CLOCK_SKEW_SECONDS,
        },
        JwtVcVerificationOptions {
            now_unix: NOW_UNIX,
            clock_skew_seconds: MAX_JWT_VC_CLOCK_SKEW_SECONDS + 1,
        },
        JwtVcVerificationOptions {
            now_unix: u64::MAX,
            clock_skew_seconds: 1,
        },
    ];

    for case in cases {
        let error = verify_jwt_vc(&jwt, &key.jwk, &key.public, &case)
            .expect_err("invalid verification options must fail closed");
        assert_eq!(error, JwtVcEnvelopeError::InvalidVerificationTime);
    }
}

#[test]
fn jwt_vc_accepts_maximum_clock_skew() {
    let key = gen_ed25519();
    let jwt = issue_jwt_vc(&issue_input(&key)).expect("JWT-VC must issue");

    verify_jwt_vc(
        &jwt,
        &key.jwk,
        &key.public,
        &JwtVcVerificationOptions {
            now_unix: 1_800_000_000 + MAX_JWT_VC_CLOCK_SKEW_SECONDS - 1,
            clock_skew_seconds: MAX_JWT_VC_CLOCK_SKEW_SECONDS,
        },
    )
    .expect("maximum supported skew must be accepted");
}

#[test]
fn jwt_vc_issue_rejects_negative_numeric_dates() {
    let key = gen_ed25519();
    let mut input = issue_input(&key);
    input.not_before_unix = Some(-5);

    let error = issue_jwt_vc(&input).expect_err("negative nbf must fail before signing");

    assert_eq!(error, JwtVcEnvelopeError::InvalidTemporalClaim);
}
