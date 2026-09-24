// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Test coverage for this crate.

#![allow(
    missing_docs,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::print_stderr
)]

use codec_base64url::base64url_to_bytes;
use crypto_core::Algorithm;
use crypto_dispatch::generate_keypair;
use envelopes_jwk::{Jwk, OkpJwk};
#[cfg(feature = "conformance-vectors")]
use identity_vc_ietf_sd_jwt::issue_ietf_sd_jwt_vc_deterministic;
use identity_vc_ietf_sd_jwt::{
    extract_me_profile_merkle_binding, issue_ietf_sd_jwt_vc, verify_ietf_sd_jwt_vc,
    verify_me_profile_merkle_binding, IetfSdJwtIssueInput, IetfSdJwtJwtType, IetfSdJwtVcError,
    MeProfileMerkleBinding, ME_PROFILE_EXTENSION_CLAIM,
};
use serde_json::{json, Map, Value};
use zeroize::Zeroize;

fn issuer_jwk_from_public_key(public_key: &[u8]) -> Jwk {
    Jwk::Okp(OkpJwk {
        kty: "OKP".to_string(),
        crv: "Ed25519".to_string(),
        x: codec_base64url::bytes_to_base64url(public_key),
        alg: Some("EdDSA".to_string()),
        kid: Some("issuer-key-1".to_string()),
        use_: None,
    })
}

fn decode_jwt_header_payload(jwt: &str) -> (Value, Value) {
    let parts: Vec<&str> = jwt.split('.').collect();
    assert_eq!(parts.len(), 3, "jwt must have 3 parts");
    let header: Value = serde_json::from_slice(&base64url_to_bytes(parts[0]).expect("header b64u"))
        .expect("header json");
    let payload: Value =
        serde_json::from_slice(&base64url_to_bytes(parts[1]).expect("payload b64u"))
            .expect("payload json");
    (header, payload)
}

#[test]
fn issue_output_is_valid_ietf_compact_with_trailing_tilde() {
    let (issuer_pub, issuer_priv) = generate_keypair(Algorithm::Ed25519).expect("keygen");
    let issuer_jwk = issuer_jwk_from_public_key(&issuer_pub);

    let mut input = IetfSdJwtIssueInput::new("did:me:issuer:123");
    input.subject = Some("did:me:holder:abc".to_string());
    input.issued_at_unix = Some(1_738_100_000);
    input.not_before_unix = Some(1_738_100_000);
    input.expires_at_unix = Some(1_738_100_900);
    input.vct = Some("urn:example:pid:v1".to_string());
    input.jwt_type = IetfSdJwtJwtType::DcSdJwt;

    let mut public_claims = Map::new();
    public_claims.insert("aud".to_string(), json!("verifier.example"));
    input.public_claims = public_claims;

    let mut selective_claims = Map::new();
    selective_claims.insert("given_name".to_string(), json!("ALICE"));
    selective_claims.insert("family_name".to_string(), json!("DOE"));
    selective_claims.insert("age_over_18".to_string(), json!(true));
    input.selective_claims = selective_claims;

    let issued = issue_ietf_sd_jwt_vc(&input, &issuer_jwk, &issuer_priv).expect("issue");

    assert_eq!(issued.disclosures.len(), 3);
    assert_eq!(issued.disclosures_decoded.len(), 3);

    let compact = issued.to_compact().expect("compact serialization");
    assert!(compact.ends_with('~'));

    let segments: Vec<&str> = compact.split('~').collect();
    assert_eq!(segments.len(), 5); // jwt + 3 disclosures + trailing-empty
    assert!(!segments[0].is_empty());
    assert!(segments[1..4].iter().all(|s| !s.is_empty()));
    assert!(segments[4].is_empty());

    let (header, payload) = decode_jwt_header_payload(&issued.issuer_signed_jwt);
    assert_eq!(header.get("typ").and_then(Value::as_str), Some("dc+sd-jwt"));
    assert_eq!(
        payload.get("iss").and_then(Value::as_str),
        Some("did:me:issuer:123")
    );
    assert_eq!(
        payload.get("sub").and_then(Value::as_str),
        Some("did:me:holder:abc")
    );
    assert_eq!(
        payload.get("vct").and_then(Value::as_str),
        Some("urn:example:pid:v1")
    );

    let sd = payload
        .get("_sd")
        .and_then(Value::as_array)
        .expect("_sd array");
    assert_eq!(sd.len(), 3);

    assert!(payload.get("given_name").is_none());
    assert!(payload.get("family_name").is_none());
    assert!(payload.get("age_over_18").is_none());
}

#[test]
fn verify_accepts_valid_issued_sd_jwt_and_restores_claims() {
    let (issuer_pub, issuer_priv) = generate_keypair(Algorithm::Ed25519).expect("keygen");
    let issuer_jwk = issuer_jwk_from_public_key(&issuer_pub);

    let mut input = IetfSdJwtIssueInput::new("did:me:issuer:xyz");
    let mut selective_claims = Map::new();
    selective_claims.insert("email".to_string(), json!("alice@example.com"));
    selective_claims.insert("country".to_string(), json!("NL"));
    input.selective_claims = selective_claims;

    let issued = issue_ietf_sd_jwt_vc(&input, &issuer_jwk, &issuer_priv).expect("issue");
    let compact = issued.to_compact().expect("compact serialization");

    let verified = verify_ietf_sd_jwt_vc(&compact, &issuer_jwk, &issuer_pub).expect("verify");

    assert_eq!(verified.disclosures.len(), 2);
    assert_eq!(
        verified
            .disclosed_claims
            .get("email")
            .and_then(Value::as_str),
        Some("alice@example.com")
    );
    assert_eq!(
        verified
            .disclosed_claims
            .get("country")
            .and_then(Value::as_str),
        Some("NL")
    );
}

#[test]
fn verify_rejects_tampered_disclosure() {
    let (issuer_pub, issuer_priv) = generate_keypair(Algorithm::Ed25519).expect("keygen");
    let issuer_jwk = issuer_jwk_from_public_key(&issuer_pub);

    let mut input = IetfSdJwtIssueInput::new("did:me:issuer:t1");
    let mut selective_claims = Map::new();
    selective_claims.insert("age_over_21".to_string(), json!(true));
    input.selective_claims = selective_claims;

    let issued = issue_ietf_sd_jwt_vc(&input, &issuer_jwk, &issuer_priv).expect("issue");

    let mut segments: Vec<String> = issued
        .to_compact()
        .expect("compact serialization")
        .split('~')
        .map(ToString::to_string)
        .collect();

    assert!(segments.len() >= 3);
    let disclosure = segments[1].clone();
    let mut disclosure_bytes = base64url_to_bytes(&disclosure).expect("disclosure bytes");
    if let Some(first) = disclosure_bytes.first_mut() {
        *first ^= 0x01;
    }
    segments[1] = codec_base64url::bytes_to_base64url(&disclosure_bytes);

    let tampered = segments.join("~");
    let err = verify_ietf_sd_jwt_vc(&tampered, &issuer_jwk, &issuer_pub).unwrap_err();

    assert!(matches!(err, IetfSdJwtVcError::InvalidDisclosure));
}

#[test]
fn verify_rejects_wrong_issuer_key() {
    let (issuer_pub, issuer_priv) = generate_keypair(Algorithm::Ed25519).expect("keygen");
    let (wrong_pub, _) = generate_keypair(Algorithm::Ed25519).expect("keygen");

    let issuer_jwk = issuer_jwk_from_public_key(&issuer_pub);

    let mut input = IetfSdJwtIssueInput::new("did:me:issuer:t2");
    let mut selective_claims = Map::new();
    selective_claims.insert("given_name".to_string(), json!("EVE"));
    input.selective_claims = selective_claims;

    let issued = issue_ietf_sd_jwt_vc(&input, &issuer_jwk, &issuer_priv).expect("issue");
    let compact = issued.to_compact().expect("compact serialization");

    let err = verify_ietf_sd_jwt_vc(&compact, &issuer_jwk, &wrong_pub).unwrap_err();
    assert!(matches!(err, IetfSdJwtVcError::Verification));
}

#[test]
fn issue_rejects_reserved_sd_claim_keys() {
    let (issuer_pub, issuer_priv) = generate_keypair(Algorithm::Ed25519).expect("keygen");
    let issuer_jwk = issuer_jwk_from_public_key(&issuer_pub);

    let mut input = IetfSdJwtIssueInput::new("did:me:issuer:t3");
    let mut public_claims = Map::new();
    public_claims.insert("_sd".to_string(), json!(["bad"]));
    input.public_claims = public_claims;

    let err = issue_ietf_sd_jwt_vc(&input, &issuer_jwk, &issuer_priv).unwrap_err();
    assert!(matches!(err, IetfSdJwtVcError::ReservedClaimKey));
}

#[test]
fn verify_accepts_compact_without_disclosures() {
    let (issuer_pub, issuer_priv) = generate_keypair(Algorithm::Ed25519).expect("keygen");
    let issuer_jwk = issuer_jwk_from_public_key(&issuer_pub);

    let mut input = IetfSdJwtIssueInput::new("did:me:issuer:no-disclosure");
    let mut public_claims = Map::new();
    public_claims.insert("scope".to_string(), json!("openid"));
    input.public_claims = public_claims;

    let issued = issue_ietf_sd_jwt_vc(&input, &issuer_jwk, &issuer_priv).expect("issue");
    assert!(issued.disclosures.is_empty());
    let compact = issued.to_compact().expect("compact serialization");
    assert_eq!(compact.matches('~').count(), 1);

    let verified = verify_ietf_sd_jwt_vc(&compact, &issuer_jwk, &issuer_pub).expect("verify");
    assert_eq!(
        verified
            .disclosed_claims
            .get("scope")
            .and_then(Value::as_str),
        Some("openid")
    );
}

#[test]
fn issue_and_verify_supports_me_profile_merkle_extension_claim() {
    let (issuer_pub, issuer_priv) = generate_keypair(Algorithm::Ed25519).expect("keygen");
    let issuer_jwk = issuer_jwk_from_public_key(&issuer_pub);

    let mut input = IetfSdJwtIssueInput::new("did:me:issuer:zk");
    input.me_profile_merkle_binding = Some(
        MeProfileMerkleBinding::new("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "sha-256")
            .expect("binding"),
    );
    let mut selective_claims = Map::new();
    selective_claims.insert("family_name".to_string(), json!("DOE"));
    input.selective_claims = selective_claims;

    let issued = issue_ietf_sd_jwt_vc(&input, &issuer_jwk, &issuer_priv).expect("issue");
    let compact = issued.to_compact().expect("compact serialization");
    let verified = verify_ietf_sd_jwt_vc(&compact, &issuer_jwk, &issuer_pub).expect("verify");

    let payload_obj = verified.payload.as_object().expect("payload object");
    assert!(payload_obj.contains_key(ME_PROFILE_EXTENSION_CLAIM));

    let ext = extract_me_profile_merkle_binding(payload_obj)
        .expect("extract")
        .expect("present");
    assert_eq!(
        ext.merkle_root_b64u,
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    );
    assert_eq!(ext.commitment_alg, "sha-256");

    let expected_root = base64url_to_bytes(ext.merkle_root_b64u.as_str()).expect("root decodes");
    verify_me_profile_merkle_binding(payload_obj, expected_root.as_slice(), "sha-256")
        .expect("binding matches expected root");
}

#[test]
#[cfg(feature = "conformance-vectors")]
fn deterministic_issuance_is_stable_for_same_seed() {
    let (issuer_pub, issuer_priv) = generate_keypair(Algorithm::Ed25519).expect("keygen");
    let issuer_jwk = issuer_jwk_from_public_key(&issuer_pub);

    let mut input = IetfSdJwtIssueInput::new("did:me:issuer:det");
    let mut selective_claims = Map::new();
    selective_claims.insert("given_name".to_string(), json!("ALICE"));
    selective_claims.insert("family_name".to_string(), json!("DOE"));
    input.selective_claims = selective_claims;

    let one = issue_ietf_sd_jwt_vc_deterministic(&input, &issuer_jwk, &issuer_priv, 42)
        .expect("issue one");
    let two = issue_ietf_sd_jwt_vc_deterministic(&input, &issuer_jwk, &issuer_priv, 42)
        .expect("issue two");
    let three = issue_ietf_sd_jwt_vc_deterministic(&input, &issuer_jwk, &issuer_priv, 43)
        .expect("issue three");

    assert_eq!(
        one.to_compact().expect("first compact serialization"),
        two.to_compact().expect("second compact serialization")
    );
    assert_ne!(
        one.to_compact().expect("first compact serialization"),
        three.to_compact().expect("third compact serialization")
    );
}

#[test]
fn issue_rejects_oversized_and_excessively_nested_input() {
    let (issuer_pub, issuer_priv) = generate_keypair(Algorithm::Ed25519).expect("keygen");
    let issuer_jwk = issuer_jwk_from_public_key(&issuer_pub);

    let oversized_issuer = IetfSdJwtIssueInput::new("i".repeat(4097));
    assert!(matches!(
        issue_ietf_sd_jwt_vc(&oversized_issuer, &issuer_jwk, &issuer_priv),
        Err(IetfSdJwtVcError::InvalidInput)
    ));

    let mut nested = Value::Null;
    for _ in 0..40 {
        nested = json!({"nested": nested});
    }
    let mut nested_input = IetfSdJwtIssueInput::new("did:me:issuer:bounded");
    nested_input
        .selective_claims
        .insert("malicious".to_owned(), nested);
    assert!(matches!(
        issue_ietf_sd_jwt_vc(&nested_input, &issuer_jwk, &issuer_priv),
        Err(IetfSdJwtVcError::InvalidInput)
    ));
}

#[test]
fn me_profile_binding_redacts_diagnostics_and_supports_explicit_cleanup() {
    let root = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    let mut binding = MeProfileMerkleBinding::new(root, "sha-256").expect("valid binding");
    let debug = format!("{binding:?}");
    assert!(!debug.contains(root));

    binding.zeroize();
    assert!(binding.merkle_root_b64u.is_empty());
    assert!(binding.commitment_alg.is_empty());
}
