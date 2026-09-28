// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(clippy::expect_used, clippy::unwrap_used)]
#![allow(missing_docs)]

use std::cell::Cell;

use reallyme_codec::{
    base64::bytes_to_base64,
    base64url::{base64url_to_bytes, bytes_to_base64url},
};
use reallyme_credential_status::{
    build_token_status_list_payload, verify_token_status_list_jwt,
    verify_token_status_list_jwt_with_x5c, TokenStatusBits, TokenStatusListClaims,
    TokenStatusListError, TokenStatusListFreshnessPolicy, TokenStatusListInvalidReason,
    TokenStatusListProfile, TokenStatusValue, MAX_TOKEN_STATUS_X5C_CERTIFICATES,
    MAX_TOKEN_STATUS_X5C_CERTIFICATE_BYTES, MAX_TOKEN_STATUS_X5C_CHAIN_BYTES,
};
use reallyme_crypto::{
    core::Algorithm,
    dispatch::generate_keypair,
    jwk::{p256_public_key_to_jwk, Jwk, JwkOptions},
};
use reallyme_jose::jws::suites::es256::sign_p256_jose_prehash;

// These are small, valid DER values used as opaque path entries. The mock
// resolver below represents the deployment's X.509 parser and trust engine.
const TEST_LEAF_DER: &[u8] = &[0x30, 0x03, 0x02, 0x01, 0x01];
const TEST_ISSUER_DER: &[u8] = &[0x30, 0x03, 0x02, 0x01, 0x02];

fn claims() -> TokenStatusListClaims {
    TokenStatusListClaims {
        profile: TokenStatusListProfile::IetfDraft21,
        sub: "https://issuer.example/status/1".to_owned(),
        iat: 1_800_000_000,
        exp: Some(1_800_003_600),
        ttl: Some(300),
        status_list: build_token_status_list_payload(
            &[1, 2, 3, 0, 2, 1],
            TokenStatusBits::Two,
            Some("https://issuer.example/status".to_owned()),
        )
        .expect("valid fixture"),
    }
}

fn x5c_header_json(chain: &[Vec<u8>]) -> String {
    let encoded_chain: Vec<String> = chain
        .iter()
        .map(|certificate| bytes_to_base64(certificate))
        .collect();
    serde_json::json!({
        "alg": "ES256",
        "typ": "statuslist+jwt",
        "x5c": encoded_chain,
    })
    .to_string()
}

fn sign_x5c_jwt_with_header(
    claims: &TokenStatusListClaims,
    private_key: &[u8],
    protected_header_json: &str,
) -> String {
    let protected = bytes_to_base64url(protected_header_json.as_bytes());
    let payload = bytes_to_base64url(&serde_json::to_vec(claims).expect("claims serialize"));
    let signing_input = format!("{protected}.{payload}");
    let signature =
        sign_p256_jose_prehash(private_key, signing_input.as_bytes()).expect("fixture signature");
    format!("{signing_input}.{}", bytes_to_base64url(&signature))
}

fn sign_x5c_jwt(claims: &TokenStatusListClaims, private_key: &[u8], chain: &[Vec<u8>]) -> String {
    sign_x5c_jwt_with_header(claims, private_key, &x5c_header_json(chain))
}

fn verify_x5c_fixture(
    token: &str,
    public_key: &[u8],
    expected_subject: &str,
    now_unix: u64,
    freshness: TokenStatusListFreshnessPolicy,
) -> Result<reallyme_credential_status::VerifiedTokenStatusList, TokenStatusListError> {
    verify_token_status_list_jwt_with_x5c(
        token,
        |chain, verification_time| {
            (chain == [TEST_LEAF_DER.to_vec(), TEST_ISSUER_DER.to_vec()]
                && verification_time == now_unix)
                .then(|| public_key.to_vec())
        },
        expected_subject,
        now_unix,
        freshness,
    )
}

#[test]
fn authenticates_exact_chain_time_and_p256_signature() {
    let (public_key, private_key) =
        generate_keypair(Algorithm::P256).expect("fixture key generation");
    let chain = vec![TEST_LEAF_DER.to_vec(), TEST_ISSUER_DER.to_vec()];
    let token = sign_x5c_jwt(&claims(), &private_key, &chain);

    let verified = verify_x5c_fixture(
        &token,
        &public_key,
        "https://issuer.example/status/1",
        1_800_000_100,
        TokenStatusListFreshnessPolicy::default(),
    )
    .expect("trusted x5c status list must verify");

    assert_eq!(verified.packed_statuses(), [0x39, 0x06]);
    assert_eq!(verified.status(0), Ok(TokenStatusValue::Invalid));
    assert_eq!(verified.status(1), Ok(TokenStatusValue::Suspended));
    assert_eq!(
        verified.status(2),
        Err(TokenStatusListError::InvalidInput(
            TokenStatusListInvalidReason::UnsupportedStatusValue
        ))
    );
}

#[test]
fn rejects_untrusted_and_tampered_chains() {
    let (public_key, private_key) =
        generate_keypair(Algorithm::P256).expect("fixture key generation");
    let chain = vec![TEST_LEAF_DER.to_vec(), TEST_ISSUER_DER.to_vec()];
    let token = sign_x5c_jwt(&claims(), &private_key, &chain);

    let untrusted = verify_token_status_list_jwt_with_x5c(
        &token,
        |_, _| None,
        "https://issuer.example/status/1",
        1_800_000_100,
        TokenStatusListFreshnessPolicy::default(),
    )
    .expect_err("an untrusted path must fail closed");
    assert_eq!(untrusted, TokenStatusListError::CertificatePathRejected);

    let malformed_der = vec![vec![0x30, 0x01, 0xff]];
    let malformed_token = sign_x5c_jwt(&claims(), &private_key, &malformed_der);
    let malformed = verify_token_status_list_jwt_with_x5c(
        &malformed_token,
        |presented, _| {
            assert_eq!(presented, malformed_der);
            None
        },
        "https://issuer.example/status/1",
        1_800_000_100,
        TokenStatusListFreshnessPolicy::default(),
    )
    .expect_err("the path resolver must reject malformed certificate DER");
    assert_eq!(malformed, TokenStatusListError::CertificatePathRejected);

    let mut parts = token.split('.');
    let original_header = parts.next().expect("header");
    let payload = parts.next().expect("payload");
    let signature = parts.next().expect("signature");
    assert!(parts.next().is_none());
    assert!(!base64url_to_bytes(original_header)
        .expect("header base64url")
        .is_empty());
    let tampered_chain = vec![vec![0x30, 0x00], TEST_ISSUER_DER.to_vec()];
    let tampered_header = bytes_to_base64url(x5c_header_json(&tampered_chain).as_bytes());
    let tampered_token = format!("{tampered_header}.{payload}.{signature}");
    let tampered = verify_token_status_list_jwt_with_x5c(
        &tampered_token,
        |presented, _| (presented == tampered_chain).then(|| public_key.clone()),
        "https://issuer.example/status/1",
        1_800_000_100,
        TokenStatusListFreshnessPolicy::default(),
    )
    .expect_err("x5c is authenticated by the signature");
    assert_eq!(tampered, TokenStatusListError::Authentication);
}

#[test]
fn rejects_jwk_substitution_and_unsupported_key_headers() {
    let (_, private_key) = generate_keypair(Algorithm::P256).expect("fixture key generation");
    let encoded_leaf = bytes_to_base64(TEST_LEAF_DER);
    let headers = [
        format!(
            r#"{{"alg":"ES256","typ":"statuslist+jwt","x5c":["{encoded_leaf}"],"jwk":{{"kty":"EC"}}}}"#
        ),
        format!(
            r#"{{"alg":"ES256","typ":"statuslist+jwt","x5c":["{encoded_leaf}"],"x5u":"https://issuer.example/key"}}"#
        ),
        format!(
            r#"{{"alg":"ES256","typ":"statuslist+jwt","x5c":["{encoded_leaf}"],"kid":"alternate"}}"#
        ),
    ];

    for header in headers {
        let token = sign_x5c_jwt_with_header(&claims(), &private_key, &header);
        assert_invalid_header_before_resolution(&token);
    }
}

#[test]
fn rejects_duplicate_protected_members() {
    let (_, private_key) = generate_keypair(Algorithm::P256).expect("fixture key generation");
    let encoded_leaf = bytes_to_base64(TEST_LEAF_DER);
    let duplicate = format!(
        r#"{{"alg":"ES256","typ":"statuslist+jwt","x5c":["{encoded_leaf}"],"x5c":["{encoded_leaf}"]}}"#
    );
    let token = sign_x5c_jwt_with_header(&claims(), &private_key, &duplicate);

    assert_invalid_header_before_resolution(&token);
}

#[test]
fn rejects_empty_malformed_and_oversized_chains() {
    let (_, private_key) = generate_keypair(Algorithm::P256).expect("fixture key generation");
    let too_many = vec![vec![1_u8]; MAX_TOKEN_STATUS_X5C_CERTIFICATES + 1];
    let oversized = vec![vec![1_u8; MAX_TOKEN_STATUS_X5C_CERTIFICATE_BYTES + 1]];
    let aggregate_oversized = vec![
        vec![1_u8; MAX_TOKEN_STATUS_X5C_CERTIFICATE_BYTES],
        vec![2_u8; MAX_TOKEN_STATUS_X5C_CERTIFICATE_BYTES],
        vec![3_u8; MAX_TOKEN_STATUS_X5C_CERTIFICATE_BYTES],
        vec![4_u8; MAX_TOKEN_STATUS_X5C_CERTIFICATE_BYTES],
        vec![
            5_u8;
            MAX_TOKEN_STATUS_X5C_CHAIN_BYTES
                .checked_sub(4 * MAX_TOKEN_STATUS_X5C_CERTIFICATE_BYTES)
                .expect("fixture arithmetic")
                + 1
        ],
    ];
    let headers = [
        r#"{"alg":"ES256","typ":"statuslist+jwt","x5c":[]}"#.to_owned(),
        r#"{"alg":"ES256","typ":"statuslist+jwt","x5c":["***"]}"#.to_owned(),
        r#"{"alg":"ES256","typ":"statuslist+jwt","x5c":[""]}"#.to_owned(),
        x5c_header_json(&too_many),
        x5c_header_json(&oversized),
        x5c_header_json(&aggregate_oversized),
    ];

    for header in headers {
        let token = sign_x5c_jwt_with_header(&claims(), &private_key, &header);
        assert_invalid_header_before_resolution(&token);
    }
}

#[test]
fn raw_key_verifier_continues_to_reject_embedded_x5c() {
    let (public_key, private_key) =
        generate_keypair(Algorithm::P256).expect("fixture key generation");
    let chain = vec![TEST_LEAF_DER.to_vec(), TEST_ISSUER_DER.to_vec()];
    let token = sign_x5c_jwt(&claims(), &private_key, &chain);
    let jwk = Jwk::Ec(
        p256_public_key_to_jwk(
            &public_key,
            JwkOptions {
                alg: true,
                use_sig: true,
                use_enc: false,
                kid: None,
            },
        )
        .expect("fixture JWK"),
    );

    let error = verify_token_status_list_jwt(
        &token,
        &jwk,
        &public_key,
        "https://issuer.example/status/1",
        1_800_000_100,
        TokenStatusListFreshnessPolicy::default(),
    )
    .expect_err("the raw-key API must continue to reject embedded key material");
    assert_eq!(error, TokenStatusListError::Authentication);
}

#[test]
fn rejects_signature_key_mismatch_and_invalid_leaf_key() {
    let (_, private_key) = generate_keypair(Algorithm::P256).expect("fixture key generation");
    let (other_public_key, _) = generate_keypair(Algorithm::P256).expect("fixture key generation");
    let chain = vec![TEST_LEAF_DER.to_vec(), TEST_ISSUER_DER.to_vec()];
    let token = sign_x5c_jwt(&claims(), &private_key, &chain);

    let mismatch = verify_token_status_list_jwt_with_x5c(
        &token,
        |_, _| Some(other_public_key),
        "https://issuer.example/status/1",
        1_800_000_100,
        TokenStatusListFreshnessPolicy::default(),
    )
    .expect_err("the authenticated leaf key must verify the JWS");
    assert_eq!(mismatch, TokenStatusListError::Authentication);

    let invalid_key = verify_token_status_list_jwt_with_x5c(
        &token,
        |_, _| Some(vec![0_u8; 65]),
        "https://issuer.example/status/1",
        1_800_000_100,
        TokenStatusListFreshnessPolicy::default(),
    )
    .expect_err("an invalid P-256 point must fail closed");
    assert_eq!(invalid_key, TokenStatusListError::InvalidCertificateKey);
}

#[test]
fn retains_subject_expiration_and_freshness_checks() {
    let (public_key, private_key) =
        generate_keypair(Algorithm::P256).expect("fixture key generation");
    let chain = vec![TEST_LEAF_DER.to_vec(), TEST_ISSUER_DER.to_vec()];
    let token = sign_x5c_jwt(&claims(), &private_key, &chain);

    let wrong_subject = verify_x5c_fixture(
        &token,
        &public_key,
        "https://issuer.example/status/other",
        1_800_000_100,
        TokenStatusListFreshnessPolicy::default(),
    )
    .expect_err("subject mismatch must fail closed");
    assert_eq!(wrong_subject, TokenStatusListError::SubjectMismatch);

    let expired = verify_x5c_fixture(
        &token,
        &public_key,
        "https://issuer.example/status/1",
        1_800_003_600,
        TokenStatusListFreshnessPolicy::default(),
    )
    .expect_err("expiration boundary must fail closed");
    assert_eq!(expired, TokenStatusListError::Expired);

    let mut open_ended = claims();
    open_ended.exp = None;
    open_ended.ttl = None;
    let stale_token = sign_x5c_jwt(&open_ended, &private_key, &chain);
    let stale = verify_x5c_fixture(
        &stale_token,
        &public_key,
        "https://issuer.example/status/1",
        open_ended.iat + 300,
        TokenStatusListFreshnessPolicy { max_age_secs: 300 },
    )
    .expect_err("local freshness boundary must fail closed");
    assert_eq!(stale, TokenStatusListError::Expired);
}

fn assert_invalid_header_before_resolution(token: &str) {
    let resolver_called = Cell::new(false);
    let error = verify_token_status_list_jwt_with_x5c(
        token,
        |_, _| {
            resolver_called.set(true);
            None
        },
        "https://issuer.example/status/1",
        1_800_000_100,
        TokenStatusListFreshnessPolicy::default(),
    )
    .expect_err("invalid x5c protected header must fail closed");
    assert_eq!(error, TokenStatusListError::InvalidCertificateChain);
    assert!(!resolver_called.get());
}
