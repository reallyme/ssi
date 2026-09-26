// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
// SPDX-FileCopyrightText: Copyright (c) 2024 DSR Corporation, Denver, Colorado.
// https://www.dsr-corporation.com
//
// SPDX-License-Identifier: Apache-2.0
//! Reference demo coverage for the IETF SD-JWT VC crate.

#![cfg(feature = "reference-tests")]
#![allow(
    missing_docs,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::print_stderr
)]

use crypto_core::Algorithm;
use crypto_dispatch::generate_keypair;
use crypto_sha2_256::digest as sha2_256_digest;
use envelopes_jwk::{Jwk, OkpJwk};
use identity_vc_ietf_sd_jwt::{
    issue_ietf_sd_jwt_vc, verify_ietf_sd_jwt_vc, IetfSdJwtIssueInput, IetfSdJwtJwtType,
    IetfSdJwtTemporalPolicy,
};
use serde_json::{Map, Value};

/// Verifier clock inside every fixture credential's validity window.
const VERIFY_TEMPORAL_POLICY: IetfSdJwtTemporalPolicy = IetfSdJwtTemporalPolicy::new(1_738_100_100);

mod utils;

use utils::fixtures::{
    ADDRESS_CLAIMS, ARRAYED_CLAIMS, COMPLEX_EIDAS_CLAIMS, COMPLEX_EKYC_CLAIMS, NESTED_ARRAY_CLAIMS,
};

fn issuer_jwk_from_public_key(public_key: &[u8]) -> Jwk {
    Jwk::Okp(OkpJwk {
        kty: "OKP".to_string(),
        crv: "Ed25519".to_string(),
        x: codec_base64url::bytes_to_base64url(public_key),
        alg: Some("EdDSA".to_string()),
        kid: Some("issuer-ref-key".to_string()),
        use_: None,
    })
}

fn fixture_cases() -> [(&'static str, &'static str); 5] {
    [
        ("address", ADDRESS_CLAIMS),
        ("arrayed", ARRAYED_CLAIMS),
        ("nested_array", NESTED_ARRAY_CLAIMS),
        ("complex_eidas", COMPLEX_EIDAS_CLAIMS),
        ("complex_ekyc", COMPLEX_EKYC_CLAIMS),
    ]
}

fn parse_fixture_to_input(case_json: &str) -> IetfSdJwtIssueInput {
    let parsed: Value = serde_json::from_str(case_json).expect("fixture JSON must parse");
    let mut obj = parsed
        .as_object()
        .expect("fixture root must be object")
        .clone();

    let issuer = obj
        .remove("iss")
        .and_then(|v| v.as_str().map(ToString::to_string))
        .unwrap_or_else(|| "https://example.com/issuer".to_string());

    let mut input = IetfSdJwtIssueInput::new(issuer);

    input.subject = obj
        .remove("sub")
        .and_then(|v| v.as_str().map(ToString::to_string));

    input.issued_at_unix = obj.remove("iat").and_then(|v| v.as_u64());
    input.not_before_unix = obj.remove("nbf").and_then(|v| v.as_u64());
    input.expires_at_unix = obj.remove("exp").and_then(|v| v.as_u64());

    if let Some(vct) = obj
        .remove("vct")
        .and_then(|v| v.as_str().map(ToString::to_string))
    {
        input.vct = Some(vct);
    }

    // For reference tests, disclose all remaining application claims.
    let selective_claims: Map<String, Value> = obj;
    input.selective_claims = selective_claims;
    input.jwt_type = IetfSdJwtJwtType::DcSdJwt;

    input
}

fn decode_payload(jwt: &str) -> Value {
    let parts: Vec<&str> = jwt.split('.').collect();
    assert_eq!(parts.len(), 3, "issuer JWT must be compact JWS");
    let payload_bytes = codec_base64url::base64url_to_bytes(parts[1]).expect("payload b64u decode");
    serde_json::from_slice(&payload_bytes).expect("payload JSON decode")
}

#[test]
fn reference_fixtures_roundtrip_and_verify() {
    let (issuer_pub, issuer_priv) = generate_keypair(Algorithm::Ed25519).expect("keygen");
    let issuer_jwk = issuer_jwk_from_public_key(&issuer_pub);

    for (name, fixture) in fixture_cases() {
        let input = parse_fixture_to_input(fixture);

        let issued = issue_ietf_sd_jwt_vc(&input, &issuer_jwk, &issuer_priv)
            .unwrap_or_else(|e| panic!("{name}: issue failed: {e}"));

        let compact = issued.to_compact().expect("compact serialization");
        let verified =
            verify_ietf_sd_jwt_vc(&compact, &issuer_jwk, &issuer_pub, &VERIFY_TEMPORAL_POLICY)
                .unwrap_or_else(|e| panic!("{name}: verify failed: {e}"));

        let payload = decode_payload(&issued.issuer_signed_jwt);
        let payload_obj = payload
            .as_object()
            .unwrap_or_else(|| panic!("{name}: payload not object"));

        // IETF SD-JWT core claims are present and well-formed.
        assert_eq!(
            payload_obj.get("_sd_alg").and_then(Value::as_str),
            Some("sha-256"),
            "{name}: unexpected _sd_alg"
        );

        let sd_arr = payload_obj
            .get("_sd")
            .and_then(Value::as_array)
            .unwrap_or_else(|| panic!("{name}: missing _sd array"));

        assert_eq!(
            sd_arr.len(),
            issued.disclosures.len(),
            "{name}: _sd digest count mismatch"
        );

        // Critical spec detail: digest is over raw disclosure string bytes.
        for disclosure_b64u in &issued.disclosures {
            let digest_b64u = codec_base64url::bytes_to_base64url(
                sha2_256_digest(disclosure_b64u.as_bytes()).as_bytes(),
            );
            assert!(
                sd_arr
                    .iter()
                    .filter_map(Value::as_str)
                    .any(|s| s == digest_b64u),
                "{name}: disclosure digest not found in _sd"
            );
        }

        // Verified claim reconstruction must include all disclosed app claims.
        for (k, v) in &input.selective_claims {
            assert_eq!(
                verified.disclosed_claims.get(k),
                Some(v),
                "{name}: disclosed claim mismatch for key {k}"
            );
        }

        assert!(verified.kb_jwt.is_none(), "{name}: kb_jwt should be absent");
    }
}

#[test]
fn reference_fixtures_emit_expected_typ_and_compact_shape() {
    let (issuer_pub, issuer_priv) = generate_keypair(Algorithm::Ed25519).expect("keygen");
    let issuer_jwk = issuer_jwk_from_public_key(&issuer_pub);

    for (name, fixture) in fixture_cases() {
        let input = parse_fixture_to_input(fixture);
        let issued = issue_ietf_sd_jwt_vc(&input, &issuer_jwk, &issuer_priv)
            .unwrap_or_else(|e| panic!("{name}: issue failed: {e}"));

        let compact = issued.to_compact().expect("compact serialization");
        assert!(compact.ends_with('~'), "{name}: compact must end with '~'");

        let parts: Vec<&str> = issued.issuer_signed_jwt.split('.').collect();
        assert_eq!(parts.len(), 3, "{name}: JWT must have 3 segments");

        let header_bytes = codec_base64url::base64url_to_bytes(parts[0]).expect("header decode");
        let header: Value = serde_json::from_slice(&header_bytes).expect("header parse");
        assert_eq!(
            header.get("typ").and_then(Value::as_str),
            Some("dc+sd-jwt"),
            "{name}: typ mismatch"
        );
    }
}
