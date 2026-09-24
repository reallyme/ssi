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

use codec_base64url::{base64url_to_bytes, bytes_to_base64url};
use crypto_core::Algorithm;
use crypto_dispatch::generate_keypair;
use envelopes_jwk::{Jwk, OkpJwk};
use envelopes_jwt::jwt::{encode_signed_jwt_with_header_options, JwtHeaderEncodeOptions};
use identity_vc_ietf_sd_jwt::{
    issue_rfc9901_sd_jwt, verify_ietf_sd_jwt_vc, verify_rfc9901_sd_jwt, DecoyPolicy,
    IetfSdJwtVcError, KbJwtBuildParams, KbJwtVerifyParams, Rfc9901IssueInput, SdJwtArtifact,
    SelectiveDisclosureStrategy,
};
use serde_json::{json, Value};

fn issuer_jwk_from_public_key(public_key: &[u8]) -> Jwk {
    Jwk::Okp(OkpJwk {
        kty: "OKP".to_string(),
        crv: "Ed25519".to_string(),
        x: bytes_to_base64url(public_key),
        alg: Some("EdDSA".to_string()),
        kid: Some("issuer-key-rfc9901".to_string()),
        use_: None,
    })
}

fn decode_payload(jwt: &str) -> Value {
    let parts: Vec<&str> = jwt.split('.').collect();
    assert_eq!(parts.len(), 3);
    let payload = base64url_to_bytes(parts[1]).expect("payload b64u decode");
    serde_json::from_slice(&payload).expect("payload json decode")
}

#[test]
fn default_issuance_uses_fresh_cryptographic_salts() {
    let (issuer_pub, issuer_priv) = generate_keypair(Algorithm::Ed25519).expect("keygen");
    let issuer_jwk = issuer_jwk_from_public_key(&issuer_pub);
    let first_input =
        Rfc9901IssueInput::new("https://example.com/issuer", json!({"given_name": "Ada"}));
    let second_input =
        Rfc9901IssueInput::new("https://example.com/issuer", json!({"given_name": "Ada"}));

    let first =
        issue_rfc9901_sd_jwt(&first_input, &issuer_jwk, &issuer_priv).expect("first issuance");
    let second =
        issue_rfc9901_sd_jwt(&second_input, &issuer_jwk, &issuer_priv).expect("second issuance");

    assert_eq!(first.disclosures.len(), 1);
    assert_eq!(second.disclosures.len(), 1);
    assert_ne!(first.disclosures, second.disclosures);
}

#[test]
fn credential_verifiers_reject_missing_and_generic_issuer_types() {
    let (issuer_pub, issuer_priv) = generate_keypair(Algorithm::Ed25519).expect("keygen");
    let issuer_jwk = issuer_jwk_from_public_key(&issuer_pub);
    let input = Rfc9901IssueInput::new("https://example.com/issuer", json!({"given_name": "Ada"}));
    for issuer_type in [None, Some("JWT".to_owned())] {
        let mut issued = issue_rfc9901_sd_jwt(&input, &issuer_jwk, &issuer_priv).expect("issuance");
        let payload = decode_payload(&issued.issuer_signed_jwt);
        let mut invalid = SdJwtArtifact {
            issuer_signed_jwt: encode_signed_jwt_with_header_options(
                &payload,
                &issuer_jwk,
                &issuer_priv,
                &JwtHeaderEncodeOptions::new(issuer_type),
            )
            .expect("signed issuer JWT"),
            disclosures: core::mem::take(&mut issued.disclosures),
            kb_jwt: None,
            records: core::mem::take(&mut issued.records),
        };

        assert!(matches!(
            verify_rfc9901_sd_jwt(&invalid, &issuer_jwk, &issuer_pub, None),
            Err(IetfSdJwtVcError::Verification)
        ));

        let compact = invalid.to_compact().expect("compact serialization");
        assert!(verify_ietf_sd_jwt_vc(&compact, &issuer_jwk, &issuer_pub).is_err());

        invalid.disclosures.clear();
    }
}

#[test]
fn recursive_all_levels_and_json_serialization_parity() {
    let (issuer_pub, issuer_priv) = generate_keypair(Algorithm::Ed25519).expect("keygen");
    let issuer_jwk = issuer_jwk_from_public_key(&issuer_pub);

    let claims = json!({
        "verified_claims": {
            "verification": {
                "trust_framework": "eidas",
                "assurance_level": "high",
                "evidence": [
                    {
                        "type": "document",
                        "time": "2022-04-22T11:30Z",
                        "document": {
                            "type": "idcard",
                            "issuer": {
                                "name": "c_d612",
                                "country": "IT"
                            },
                            "number": "154554",
                            "date_of_issuance": "2021-03-23",
                            "date_of_expiry": "2031-03-22"
                        }
                    }
                ]
            },
            "claims": {
                "person_unique_identifier": "TINIT-fc0d9684-1bf0-4220-9642-8fe652c8c040",
                "given_name": "Raffaello",
                "family_name": "Mascetti",
                "date_of_birth": "1922-03-13",
                "gender": "M",
                "place_of_birth": {
                    "country": "IT",
                    "locality": "Firenze"
                },
                "nationalities": ["IT"]
            }
        },
        "birth_middle_name": "Lello"
    });

    let mut input = Rfc9901IssueInput::new("https://example.com/issuer", claims);
    input.strategy = SelectiveDisclosureStrategy::AllLevels;

    let artifact = issue_rfc9901_sd_jwt(&input, &issuer_jwk, &issuer_priv).expect("issue");
    assert!(!artifact.disclosures.is_empty());

    let compact = artifact.to_compact().expect("compact serialization");
    let reparsed = SdJwtArtifact::from_compact(&compact).expect("from compact");
    assert_eq!(reparsed.disclosures.len(), artifact.disclosures.len());

    let json = artifact.to_json_string().expect("to json");
    let from_json = SdJwtArtifact::from_json_string(&json).expect("from json");
    assert_eq!(from_json.issuer_signed_jwt, artifact.issuer_signed_jwt);
    assert_eq!(from_json.disclosures, artifact.disclosures);

    let verified =
        verify_rfc9901_sd_jwt(&artifact, &issuer_jwk, &issuer_pub, None).expect("verify");
    let payload = verified.payload.as_object().expect("payload obj");
    assert_eq!(
        payload.get("iss").and_then(Value::as_str),
        Some("https://example.com/issuer")
    );
}

#[test]
fn artifact_boundaries_reject_oversized_disclosure_fanout_and_values() {
    let fanout_json = serde_json::json!({
        "issuer_signed_jwt": "a.b.c",
        "disclosures": vec!["d"; 257],
        "kb_jwt": null,
        "records": []
    })
    .to_string();
    assert!(matches!(
        SdJwtArtifact::from_json_string(&fanout_json),
        Err(IetfSdJwtVcError::Serialization)
    ));

    let oversized = SdJwtArtifact {
        issuer_signed_jwt: "a.b.c".to_owned(),
        disclosures: vec!["d".repeat(4097)],
        kb_jwt: None,
        records: Vec::new(),
    };
    assert!(matches!(
        oversized.to_compact(),
        Err(IetfSdJwtVcError::InvalidCompactFormat)
    ));
}

#[test]
fn top_level_vs_all_levels_vs_json_paths_strategy() {
    let (issuer_pub, issuer_priv) = generate_keypair(Algorithm::Ed25519).expect("keygen");
    let issuer_jwk = issuer_jwk_from_public_key(&issuer_pub);

    let claims = json!({
      "verified_claims": {
        "verification": {
          "trust_framework": "de_aml",
          "time": "2012-04-23T18:25Z",
          "verification_process": "f24c6f-6d3f-4ec5-973e-b0d8506f3bc7",
          "evidence": [{
            "type": "document",
            "method": "pipp",
            "time": "2012-04-22T11:30Z",
            "document": {
              "type": "idcard",
              "issuer": {"name": "Stadt Augsburg", "country": "DE"},
              "number": "53554554",
              "date_of_issuance": "2010-03-23",
              "date_of_expiry": "2020-03-22"
            }
          }]
        },
        "claims": {
          "given_name": "Max",
          "family_name": "Müller",
          "nationalities": ["DE"],
          "birthdate": "1956-01-28",
          "place_of_birth": {"country": "IS", "locality": "Þykkvabæjarklaustur"},
          "address": {
            "locality": "Maxstadt",
            "postal_code": "12344",
            "country": "DE",
            "street_address": "Weidenstraße 22"
          }
        }
      },
      "birth_middle_name": "Timotheus",
      "salutation": "Dr.",
      "msisdn": "49123456789"
    });

    let mut top = Rfc9901IssueInput::new("https://example.com/issuer", claims.clone());
    top.strategy = SelectiveDisclosureStrategy::TopLevel;

    let mut all = Rfc9901IssueInput::new("https://example.com/issuer", claims.clone());
    all.strategy = SelectiveDisclosureStrategy::AllLevels;

    let mut custom = Rfc9901IssueInput::new("https://example.com/issuer", claims);
    custom.strategy = SelectiveDisclosureStrategy::JsonPaths;
    custom.custom_json_paths = vec![
        "$.verified_claims.verification.time".to_string(),
        "$.verified_claims.verification.evidence[0].method".to_string(),
        "$.verified_claims.claims.given_name".to_string(),
        "$.verified_claims.claims.family_name".to_string(),
        "$.verified_claims.claims.address".to_string(),
    ];

    let a_top = issue_rfc9901_sd_jwt(&top, &issuer_jwk, &issuer_priv).expect("issue top");
    let a_all = issue_rfc9901_sd_jwt(&all, &issuer_jwk, &issuer_priv).expect("issue all");
    let a_custom = issue_rfc9901_sd_jwt(&custom, &issuer_jwk, &issuer_priv).expect("issue custom");

    assert!(a_all.disclosures.len() > a_top.disclosures.len());
    assert!(a_custom.disclosures.len() < a_all.disclosures.len());

    verify_rfc9901_sd_jwt(&a_top, &issuer_jwk, &issuer_pub, None).expect("verify top");
    verify_rfc9901_sd_jwt(&a_all, &issuer_jwk, &issuer_pub, None).expect("verify all");
    verify_rfc9901_sd_jwt(&a_custom, &issuer_jwk, &issuer_pub, None).expect("verify custom");
}

#[test]
fn decoy_digests_are_added_and_do_not_break_verification() {
    let (issuer_pub, issuer_priv) = generate_keypair(Algorithm::Ed25519).expect("keygen");
    let issuer_jwk = issuer_jwk_from_public_key(&issuer_pub);

    let claims = json!({"name": "Alice", "address": {"country": "NL"}});

    let mut input = Rfc9901IssueInput::new("https://example.com/issuer", claims);
    input.strategy = SelectiveDisclosureStrategy::TopLevel;
    input.decoys = DecoyPolicy {
        object_decoys: 3,
        array_decoys: 2,
    };

    let artifact = issue_rfc9901_sd_jwt(&input, &issuer_jwk, &issuer_priv).expect("issue");
    let payload = decode_payload(&artifact.issuer_signed_jwt);
    let sd_count = payload
        .get("_sd")
        .and_then(Value::as_array)
        .map(|a| a.len())
        .expect("_sd array");

    assert!(sd_count > artifact.disclosures.len());

    verify_rfc9901_sd_jwt(&artifact, &issuer_jwk, &issuer_pub, None).expect("verify");
}

#[test]
fn holder_presentation_api_and_kb_jwt_binding_work() {
    let (issuer_pub, issuer_priv) = generate_keypair(Algorithm::Ed25519).expect("keygen");
    let issuer_jwk = issuer_jwk_from_public_key(&issuer_pub);

    let (holder_pub, holder_priv) = generate_keypair(Algorithm::Ed25519).expect("keygen");
    let holder_jwk = issuer_jwk_from_public_key(&holder_pub);

    let claims = json!({
        "given_name": "Max",
        "family_name": "Müller",
        "address": {"country": "DE", "postal_code": "12344"}
    });

    let mut input = Rfc9901IssueInput::new("https://example.com/issuer", claims);
    input.strategy = SelectiveDisclosureStrategy::AllLevels;
    input.confirmation_jwk = Some(holder_jwk.clone());

    let artifact = issue_rfc9901_sd_jwt(&input, &issuer_jwk, &issuer_priv).expect("issue");

    let select = vec!["$.given_name".to_string(), "$.address.country".to_string()];

    let presentation = artifact
        .holder_presentation_by_paths(
            &select,
            Some(KbJwtBuildParams {
                holder_jwk: &holder_jwk,
                holder_private_key: &holder_priv,
                audience: "https://verifier.example",
                nonce: "nonce-123",
                iat_unix: 1_738_100_000,
            }),
        )
        .expect("presentation");

    assert!(presentation.kb_jwt.is_some());
    let kb_payload = decode_payload(presentation.kb_jwt.as_deref().expect("KB-JWT exists"));
    assert_eq!(
        kb_payload
            .as_object()
            .expect("KB-JWT payload is an object")
            .keys()
            .map(String::as_str)
            .collect::<std::collections::BTreeSet<_>>(),
        std::collections::BTreeSet::from(["aud", "iat", "nonce", "sd_hash"])
    );
    assert!(
        presentation.disclosures.len() >= 2,
        "presentation should include selected disclosures and required parent disclosures"
    );

    let compact_presentation = presentation.to_compact().expect("compact presentation");
    let legacy_error = verify_ietf_sd_jwt_vc(&compact_presentation, &issuer_jwk, &issuer_pub)
        .expect_err("issuer-only verifier must reject holder-bound input");
    assert!(matches!(legacy_error, IetfSdJwtVcError::MissingKeyBinding));

    verify_rfc9901_sd_jwt(
        &presentation,
        &issuer_jwk,
        &issuer_pub,
        Some(KbJwtVerifyParams {
            holder_jwk: &holder_jwk,
            holder_public_key: &holder_pub,
            expected_audience: "https://verifier.example",
            expected_nonce: "nonce-123",
            now_unix: 1_738_100_100,
            max_iat_age_seconds: 300,
            max_future_iat_skew_seconds: 60,
        }),
    )
    .expect("verify with kb");

    let future_iat = artifact
        .holder_presentation_by_paths(
            &select,
            Some(KbJwtBuildParams {
                holder_jwk: &holder_jwk,
                holder_private_key: &holder_priv,
                audience: "https://verifier.example",
                nonce: "nonce-123",
                iat_unix: 1_738_100_161,
            }),
        )
        .expect("future-issued presentation fixture");
    let future_error = verify_rfc9901_sd_jwt(
        &future_iat,
        &issuer_jwk,
        &issuer_pub,
        Some(KbJwtVerifyParams {
            holder_jwk: &holder_jwk,
            holder_public_key: &holder_pub,
            expected_audience: "https://verifier.example",
            expected_nonce: "nonce-123",
            now_unix: 1_738_100_100,
            max_iat_age_seconds: 300,
            max_future_iat_skew_seconds: 60,
        }),
    )
    .expect_err("KB-JWT iat beyond allowed clock skew must fail");
    assert!(matches!(future_error, IetfSdJwtVcError::Verification));

    let stale_iat = artifact
        .holder_presentation_by_paths(
            &select,
            Some(KbJwtBuildParams {
                holder_jwk: &holder_jwk,
                holder_private_key: &holder_priv,
                audience: "https://verifier.example",
                nonce: "nonce-123",
                iat_unix: 1_738_099_739,
            }),
        )
        .expect("stale presentation fixture");
    let stale_error = verify_rfc9901_sd_jwt(
        &stale_iat,
        &issuer_jwk,
        &issuer_pub,
        Some(KbJwtVerifyParams {
            holder_jwk: &holder_jwk,
            holder_public_key: &holder_pub,
            expected_audience: "https://verifier.example",
            expected_nonce: "nonce-123",
            now_unix: 1_738_100_100,
            max_iat_age_seconds: 300,
            max_future_iat_skew_seconds: 60,
        }),
    )
    .expect_err("KB-JWT older than the verifier freshness window must fail");
    assert!(matches!(stale_error, IetfSdJwtVcError::Verification));

    // RFC 9901 §§3.3 and 7.3: the issuer-signed `cnf` claim makes key
    // binding mandatory for this verification policy. Removing the KB-JWT
    // must fail even when the caller omits explicit KB verification options.
    let presentation_json = presentation
        .to_json_string()
        .expect("serialize bound presentation");
    let mut stripped =
        SdJwtArtifact::from_json_string(&presentation_json).expect("parse presentation copy");
    stripped.kb_jwt = None;
    let error = verify_rfc9901_sd_jwt(&stripped, &issuer_jwk, &issuer_pub, None)
        .expect_err("cnf-bound presentation requires a KB-JWT");
    assert!(matches!(error, IetfSdJwtVcError::MissingKeyBinding));

    let unbound_input =
        Rfc9901IssueInput::new("https://example.com/issuer", json!({"given_name": "Alice"}));
    let mut unbound =
        issue_rfc9901_sd_jwt(&unbound_input, &issuer_jwk, &issuer_priv).expect("issue unbound");
    unbound.kb_jwt = presentation.kb_jwt.clone();
    let error = verify_rfc9901_sd_jwt(&unbound, &issuer_jwk, &issuer_pub, None)
        .expect_err("an unconfigured KB-JWT must not be ignored");
    assert!(matches!(error, IetfSdJwtVcError::MissingKeyBinding));

    let (attacker_public_key, attacker_private_key) =
        generate_keypair(Algorithm::Ed25519).expect("attacker fixture keygen");
    let attacker_jwk = issuer_jwk_from_public_key(&attacker_public_key);
    let substituted = artifact
        .holder_presentation_by_paths(
            &select,
            Some(KbJwtBuildParams {
                holder_jwk: &attacker_jwk,
                holder_private_key: &attacker_private_key,
                audience: "https://verifier.example",
                nonce: "nonce-123",
                iat_unix: 1_738_100_000,
            }),
        )
        .expect("attacker presentation is syntactically valid");
    let error = verify_rfc9901_sd_jwt(
        &substituted,
        &issuer_jwk,
        &issuer_pub,
        Some(KbJwtVerifyParams {
            holder_jwk: &attacker_jwk,
            holder_public_key: &attacker_public_key,
            expected_audience: "https://verifier.example",
            expected_nonce: "nonce-123",
            now_unix: 1_738_100_100,
            max_iat_age_seconds: 300,
            max_future_iat_skew_seconds: 60,
        }),
    )
    .expect_err("KB-JWT key must match issuer-signed cnf.jwk");
    assert!(matches!(error, IetfSdJwtVcError::Verification));
}

#[test]
fn negative_rejects_malformed_disclosures_and_mismatched_sd() {
    let (issuer_pub, issuer_priv) = generate_keypair(Algorithm::Ed25519).expect("keygen");
    let issuer_jwk = issuer_jwk_from_public_key(&issuer_pub);

    let claims = json!({"name": "Alice", "age": 30});

    let mut input = Rfc9901IssueInput::new("https://example.com/issuer", claims);
    input.strategy = SelectiveDisclosureStrategy::TopLevel;

    let artifact = issue_rfc9901_sd_jwt(&input, &issuer_jwk, &issuer_priv).expect("issue");
    let artifact_json = artifact.to_json_string().expect("serialize artifact");

    // malformed disclosure (not base64url)
    let mut bad = SdJwtArtifact::from_json_string(&artifact_json).expect("parse artifact copy");
    bad.disclosures[0] = "!!!".to_string();
    assert!(verify_rfc9901_sd_jwt(&bad, &issuer_jwk, &issuer_pub, None).is_err());

    // valid base64url but digest mismatch
    let mut mismatch =
        SdJwtArtifact::from_json_string(&artifact_json).expect("parse second artifact copy");
    let dbytes = base64url_to_bytes(&mismatch.disclosures[0]).expect("decode");
    let mut tampered = dbytes;
    if let Some(first) = tampered.first_mut() {
        *first ^= 0x01;
    }
    mismatch.disclosures[0] = bytes_to_base64url(&tampered);
    assert!(verify_rfc9901_sd_jwt(&mismatch, &issuer_jwk, &issuer_pub, None).is_err());
}
