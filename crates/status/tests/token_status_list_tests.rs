// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(clippy::expect_used, clippy::unwrap_used)]
#![allow(missing_docs)]

use reallyme_codec::base64url::bytes_to_base64url;
use reallyme_cose::{
    cose_sign1_with_options, cose_verify1, CoseSign1EncodeOptions, CoseSignatureAlgorithm, CoseType,
};
use reallyme_credential_status::{
    build_token_status_list_payload, issue_token_status_list_jwt, pack_token_status_values,
    token_status_value, verify_token_status_list_jwt, TokenStatusBits, TokenStatusListClaims,
    TokenStatusListError, TokenStatusListFreshnessPolicy, TokenStatusListInvalidReason,
    TokenStatusListProfile,
};
use reallyme_crypto::{
    core::Algorithm,
    dispatch::generate_keypair,
    jwk::{Jwk, OkpJwk},
    signer::DispatchSigner,
};
use reallyme_jose::jwt::{encode_signed_jwt_with_header_options, JwtHeaderEncodeOptions};
use std::io::Write;

fn issuer_jwk(public_key: &[u8]) -> Jwk {
    Jwk::Okp(OkpJwk {
        kty: "OKP".to_owned(),
        crv: "Ed25519".to_owned(),
        x: bytes_to_base64url(public_key),
        alg: Some("EdDSA".to_owned()),
        use_: Some("sig".to_owned()),
        kid: Some("status-list-key-1".to_owned()),
    })
}

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

#[test]
fn packs_values_least_significant_bit_first() {
    let packed =
        pack_token_status_values(&[1, 2, 3, 0], TokenStatusBits::Two).expect("valid values");
    assert_eq!(packed, vec![0x39]);
}

#[test]
fn rejects_value_that_exceeds_bit_width() {
    let error = pack_token_status_values(&[2], TokenStatusBits::One)
        .expect_err("one bit cannot encode status two");
    assert_eq!(
        error,
        TokenStatusListError::InvalidInput(TokenStatusListInvalidReason::StatusValueOutOfRange)
    );
}

#[test]
fn extracts_each_supported_packed_value_width() {
    for (bits, values) in [
        (TokenStatusBits::One, vec![0, 1, 1, 0]),
        (TokenStatusBits::Two, vec![0, 1, 2, 3]),
        (TokenStatusBits::Four, vec![0, 7, 15]),
        (TokenStatusBits::Eight, vec![0, 127, 255]),
    ] {
        let packed = pack_token_status_values(&values, bits).expect("values must pack");
        for (index, expected) in values.iter().copied().enumerate() {
            assert_eq!(
                token_status_value(&packed, bits, index).expect("index must resolve"),
                expected
            );
        }
    }
    let error = token_status_value(&[0], TokenStatusBits::Eight, 1)
        .expect_err("out-of-range index must fail");
    assert_eq!(
        error,
        TokenStatusListError::InvalidInput(TokenStatusListInvalidReason::InvalidIndex)
    );
}

#[test]
fn jwt_round_trip_authenticates_type_claims_and_compressed_bytes() {
    let (public_key, private_key) =
        generate_keypair(Algorithm::Ed25519).expect("fixture key generation");
    let jwk = issuer_jwk(&public_key);
    let token =
        issue_token_status_list_jwt(&claims(), &jwk, &private_key).expect("profile JWT must issue");

    let verified = verify_token_status_list_jwt(
        &token,
        &jwk,
        &public_key,
        "https://issuer.example/status/1",
        1_800_000_100,
        TokenStatusListFreshnessPolicy::default(),
    )
    .expect("profile JWT must verify");
    assert_eq!(verified.packed_statuses, vec![0x39, 0x06]);
    assert_eq!(verified.claims.sub, "https://issuer.example/status/1");
}

#[test]
fn jwt_provider_signer_round_trip_keeps_private_key_out_of_profile_api() {
    let (public_key, private_key) =
        generate_keypair(Algorithm::Ed25519).expect("fixture key generation");
    let jwk = issuer_jwk(&public_key);
    let signer = DispatchSigner::new(Algorithm::Ed25519, private_key);
    let token = reallyme_credential_status::issue_token_status_list_jwt_with_signer(
        &claims(),
        &jwk,
        &signer,
    )
    .expect("provider-signed JWT must issue");

    verify_token_status_list_jwt(
        &token,
        &jwk,
        &public_key,
        "https://issuer.example/status/1",
        1_800_000_100,
        TokenStatusListFreshnessPolicy::default(),
    )
    .expect("provider-signed JWT must verify");
}

#[test]
fn verifier_rejects_wrong_typ_even_with_valid_signature() {
    let (public_key, private_key) =
        generate_keypair(Algorithm::Ed25519).expect("fixture key generation");
    let jwk = issuer_jwk(&public_key);
    let token = encode_signed_jwt_with_header_options(
        &claims(),
        &jwk,
        &private_key,
        &JwtHeaderEncodeOptions::jwt(),
    )
    .expect("fixture JWT");

    let error = verify_token_status_list_jwt(
        &token,
        &jwk,
        &public_key,
        "https://issuer.example/status/1",
        1_800_000_100,
        TokenStatusListFreshnessPolicy::default(),
    )
    .expect_err("wrong typ must fail closed");
    assert_eq!(error, TokenStatusListError::Authentication);
}

#[test]
fn jwt_verifier_accepts_additional_authenticated_claims() {
    let (public_key, private_key) =
        generate_keypair(Algorithm::Ed25519).expect("fixture key generation");
    let jwk = issuer_jwk(&public_key);
    let mut extended = serde_json::to_value(claims()).expect("claims must serialize");
    extended
        .as_object_mut()
        .expect("fixture is an object")
        .insert("profile_extension".to_owned(), serde_json::json!(true));
    let token = encode_signed_jwt_with_header_options(
        &extended,
        &jwk,
        &private_key,
        &JwtHeaderEncodeOptions::new(Some("statuslist+jwt".to_owned())),
    )
    .expect("extended fixture must sign");

    verify_token_status_list_jwt(
        &token,
        &jwk,
        &public_key,
        "https://issuer.example/status/1",
        1_800_000_100,
        TokenStatusListFreshnessPolicy::default(),
    )
    .expect("draft permits additional JWT claims");
}

#[test]
fn verifier_rejects_expired_token() {
    let (public_key, private_key) =
        generate_keypair(Algorithm::Ed25519).expect("fixture key generation");
    let jwk = issuer_jwk(&public_key);
    let token =
        issue_token_status_list_jwt(&claims(), &jwk, &private_key).expect("profile JWT must issue");

    let error = verify_token_status_list_jwt(
        &token,
        &jwk,
        &public_key,
        "https://issuer.example/status/1",
        1_800_003_600,
        TokenStatusListFreshnessPolicy::default(),
    )
    .expect_err("expiration boundary must fail closed");
    assert_eq!(error, TokenStatusListError::Expired);
}

#[test]
fn draft_21_compression_vector_matches_exactly() {
    let statuses = [1, 0, 0, 1, 1, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 1];
    let payload = build_token_status_list_payload(&statuses, TokenStatusBits::One, None)
        .expect("draft vector must encode");
    assert_eq!(payload.lst, "eNrbuRgAAhcBXQ");
}

#[test]
fn supports_full_capacity_one_bit_revocation_list() {
    let values = vec![0_u8; 1_048_576];
    let payload = build_token_status_list_payload(&values, TokenStatusBits::One, None)
        .expect("full-capacity revocation list must encode within bounds");
    assert_eq!(payload.bits, 1);
    assert!(!payload.lst.is_empty());
}

#[test]
fn verifier_enforces_exact_subject_uri_binding() {
    let (public_key, private_key) =
        generate_keypair(Algorithm::Ed25519).expect("fixture key generation");
    let jwk = issuer_jwk(&public_key);
    let token =
        issue_token_status_list_jwt(&claims(), &jwk, &private_key).expect("profile JWT must issue");

    let error = verify_token_status_list_jwt(
        &token,
        &jwk,
        &public_key,
        "https://issuer.example/status/other",
        1_800_000_100,
        TokenStatusListFreshnessPolicy::default(),
    )
    .expect_err("subject mismatch must fail closed");
    assert_eq!(error, TokenStatusListError::SubjectMismatch);
}

#[test]
fn cwt_round_trip_uses_tagged_sign1_and_authenticated_type() {
    let (public_key, private_key) =
        generate_keypair(Algorithm::Ed25519).expect("fixture key generation");
    let cwt = reallyme_credential_status::issue_token_status_list_cwt(
        &claims(),
        CoseSignatureAlgorithm::Ed25519,
        &private_key,
        Some(b"status-list-key-1"),
    )
    .expect("profile CWT must issue");

    let verified = reallyme_credential_status::verify_token_status_list_cwt(
        &cwt,
        CoseSignatureAlgorithm::Ed25519,
        |algorithm, kid| {
            (algorithm == Algorithm::Ed25519 && kid == b"status-list-key-1")
                .then(|| public_key.clone())
        },
        "https://issuer.example/status/1",
        1_800_000_100,
        TokenStatusListFreshnessPolicy::default(),
    )
    .expect("profile CWT must verify");

    assert_eq!(verified.packed_statuses, vec![0x39, 0x06]);
    assert_eq!(verified.claims, claims());
}

#[test]
fn p256_cwt_round_trip_uses_cose_signature_encoding() {
    let (public_key, private_key) =
        generate_keypair(Algorithm::P256).expect("fixture key generation");
    let cwt = reallyme_credential_status::issue_token_status_list_cwt(
        &claims(),
        CoseSignatureAlgorithm::Es256,
        &private_key,
        Some(b"p256-status-key"),
    )
    .expect("P-256 profile CWT must issue");

    reallyme_credential_status::verify_token_status_list_cwt(
        &cwt,
        CoseSignatureAlgorithm::Es256,
        |algorithm, kid| {
            (algorithm == Algorithm::P256 && kid == b"p256-status-key").then(|| public_key.clone())
        },
        "https://issuer.example/status/1",
        1_800_000_100,
        TokenStatusListFreshnessPolicy::default(),
    )
    .expect("P-256 COSE signature must verify");
}

#[test]
fn cwt_verifier_rejects_wrong_authenticated_type() {
    let (public_key, private_key) =
        generate_keypair(Algorithm::Ed25519).expect("fixture key generation");
    let valid = reallyme_credential_status::issue_token_status_list_cwt(
        &claims(),
        CoseSignatureAlgorithm::Ed25519,
        &private_key,
        None,
    )
    .expect("profile CWT must issue");
    let payload = cose_verify1(&valid, |_, _| Some(public_key.clone()))
        .expect("fixture payload must authenticate");
    let wrong_type = cose_sign1_with_options(
        Algorithm::Ed25519,
        &payload,
        &private_key,
        None,
        CoseSign1EncodeOptions::tagged()
            .with_protected_type(CoseType::Text("application/other+cwt".to_owned())),
    )
    .expect("wrong-type fixture must sign");

    let error = reallyme_credential_status::verify_token_status_list_cwt(
        &wrong_type,
        CoseSignatureAlgorithm::Ed25519,
        |_, _| Some(public_key.clone()),
        "https://issuer.example/status/1",
        1_800_000_100,
        TokenStatusListFreshnessPolicy::default(),
    )
    .expect_err("wrong authenticated type must fail closed");
    assert_eq!(error, TokenStatusListError::Authentication);
}

#[test]
fn cwt_verifier_rejects_untagged_sign1() {
    let (public_key, private_key) =
        generate_keypair(Algorithm::Ed25519).expect("fixture key generation");
    let valid = reallyme_credential_status::issue_token_status_list_cwt(
        &claims(),
        CoseSignatureAlgorithm::Ed25519,
        &private_key,
        None,
    )
    .expect("profile CWT must issue");
    let payload = cose_verify1(&valid, |_, _| Some(public_key.clone()))
        .expect("fixture payload must authenticate");
    let untagged = cose_sign1_with_options(
        Algorithm::Ed25519,
        &payload,
        &private_key,
        None,
        CoseSign1EncodeOptions::new()
            .with_protected_type(CoseType::Text("application/statuslist+cwt".to_owned())),
    )
    .expect("untagged fixture must sign");

    let error = reallyme_credential_status::verify_token_status_list_cwt(
        &untagged,
        CoseSignatureAlgorithm::Ed25519,
        |_, _| Some(public_key.clone()),
        "https://issuer.example/status/1",
        1_800_000_100,
        TokenStatusListFreshnessPolicy::default(),
    )
    .expect_err("missing outer tag must fail closed");
    assert_eq!(error, TokenStatusListError::Authentication);
}

#[test]
fn issuer_rejects_malformed_compressed_status_bytes() {
    let (public_key, private_key) =
        generate_keypair(Algorithm::Ed25519).expect("fixture key generation");
    let jwk = issuer_jwk(&public_key);
    let mut invalid = claims();
    invalid.status_list.lst = bytes_to_base64url(b"not-zlib");

    let error = issue_token_status_list_jwt(&invalid, &jwk, &private_key)
        .expect_err("issuer must reject malformed compression");
    assert_eq!(
        error,
        TokenStatusListError::InvalidInput(TokenStatusListInvalidReason::InvalidCompressedList)
    );
}

#[test]
fn verifier_rejects_a_one_bit_list_above_the_entry_limit() {
    let (public_key, private_key) =
        generate_keypair(Algorithm::Ed25519).expect("fixture key generation");
    let jwk = issuer_jwk(&public_key);
    let mut oversized = claims();
    oversized.status_list.bits = 1;
    let packed = vec![0_u8; 131_073];
    let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::best());
    encoder.write_all(&packed).expect("fixture compression");
    let compressed = encoder.finish().expect("fixture compression completion");
    oversized.status_list.lst = bytes_to_base64url(&compressed);
    let token = encode_signed_jwt_with_header_options(
        &oversized,
        &jwk,
        &private_key,
        &JwtHeaderEncodeOptions::new(Some("statuslist+jwt".to_owned())),
    )
    .expect("oversized authenticated fixture must sign");

    let error = verify_token_status_list_jwt(
        &token,
        &jwk,
        &public_key,
        "https://issuer.example/status/1",
        1_800_000_100,
        TokenStatusListFreshnessPolicy::default(),
    )
    .expect_err("logical entry count above the profile limit must fail closed");
    assert_eq!(
        error,
        TokenStatusListError::InvalidInput(TokenStatusListInvalidReason::InvalidCompressedList)
    );
}

fn open_ended_claims(ttl: Option<u64>) -> TokenStatusListClaims {
    TokenStatusListClaims {
        exp: None,
        ttl,
        ..claims()
    }
}

fn verify_jwt_at(
    claims: &TokenStatusListClaims,
    now: u64,
    freshness: TokenStatusListFreshnessPolicy,
) -> Result<reallyme_credential_status::VerifiedTokenStatusList, TokenStatusListError> {
    let (public_key, private_key) =
        generate_keypair(Algorithm::Ed25519).expect("fixture key generation");
    let jwk = issuer_jwk(&public_key);
    let token = issue_token_status_list_jwt(claims, &jwk, &private_key).expect("JWT must issue");
    verify_token_status_list_jwt(
        &token,
        &jwk,
        &public_key,
        "https://issuer.example/status/1",
        now,
        freshness,
    )
}

#[test]
fn list_without_exp_is_bounded_by_local_max_age() {
    let claims = open_ended_claims(None);
    let policy = TokenStatusListFreshnessPolicy { max_age_secs: 600 };

    assert!(verify_jwt_at(&claims, claims.iat + 599, policy).is_ok());
    assert_eq!(
        verify_jwt_at(&claims, claims.iat + 600, policy).unwrap_err(),
        TokenStatusListError::Expired
    );
    assert_eq!(
        verify_jwt_at(
            &claims,
            claims.iat + reallyme_credential_status::DEFAULT_TOKEN_STATUS_LIST_MAX_AGE_SECS,
            TokenStatusListFreshnessPolicy::default(),
        )
        .unwrap_err(),
        TokenStatusListError::Expired
    );
}

#[test]
fn shorter_ttl_tightens_freshness_window() {
    let claims = open_ended_claims(Some(120));
    let policy = TokenStatusListFreshnessPolicy { max_age_secs: 600 };

    assert!(verify_jwt_at(&claims, claims.iat + 119, policy).is_ok());
    assert_eq!(
        verify_jwt_at(&claims, claims.iat + 120, policy).unwrap_err(),
        TokenStatusListError::Expired
    );
}

#[test]
fn longer_ttl_does_not_extend_local_ceiling() {
    let claims = open_ended_claims(Some(10_000));
    let policy = TokenStatusListFreshnessPolicy { max_age_secs: 600 };

    assert_eq!(
        verify_jwt_at(&claims, claims.iat + 600, policy).unwrap_err(),
        TokenStatusListError::Expired
    );
}

#[test]
fn zero_freshness_ceiling_is_rejected() {
    let claims = open_ended_claims(None);

    assert_eq!(
        verify_jwt_at(
            &claims,
            claims.iat,
            TokenStatusListFreshnessPolicy { max_age_secs: 0 },
        )
        .unwrap_err(),
        TokenStatusListError::InvalidInput(TokenStatusListInvalidReason::InvalidTimeClaims)
    );
}

#[test]
fn cwt_list_without_exp_is_bounded_by_local_max_age() {
    let claims = open_ended_claims(None);
    let (public_key, private_key) =
        generate_keypair(Algorithm::Ed25519).expect("fixture key generation");
    let cwt = reallyme_credential_status::issue_token_status_list_cwt(
        &claims,
        CoseSignatureAlgorithm::Ed25519,
        &private_key,
        Some(b"status-list-key-1"),
    )
    .expect("profile CWT must issue");
    let verify = |now: u64| {
        reallyme_credential_status::verify_token_status_list_cwt(
            &cwt,
            CoseSignatureAlgorithm::Ed25519,
            |_, _| Some(public_key.clone()),
            "https://issuer.example/status/1",
            now,
            TokenStatusListFreshnessPolicy { max_age_secs: 600 },
        )
    };

    assert!(verify(claims.iat + 599).is_ok());
    assert_eq!(
        verify(claims.iat + 600).unwrap_err(),
        TokenStatusListError::Expired
    );
}

#[test]
fn verified_list_reads_status_with_signed_bit_width() {
    let verified = verify_jwt_at(
        &claims(),
        1_800_000_100,
        TokenStatusListFreshnessPolicy::default(),
    )
    .expect("fixture must verify");

    let statuses: Vec<u8> = (0..6)
        .map(|index| verified.status(index).expect("index in range"))
        .collect();
    assert_eq!(statuses, vec![1, 2, 3, 0, 2, 1]);
    assert_eq!(
        verified.status(8).unwrap_err(),
        TokenStatusListError::InvalidInput(TokenStatusListInvalidReason::InvalidIndex)
    );
    assert_eq!(
        verified.status(usize::MAX).unwrap_err(),
        TokenStatusListError::InvalidInput(TokenStatusListInvalidReason::InvalidIndex)
    );
}
