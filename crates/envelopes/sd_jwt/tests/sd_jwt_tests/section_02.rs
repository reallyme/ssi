// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#[test]
fn verify_sd_jwt_rejects_unaccepted_issuer_typ() {
    let issuer = gen_ed25519();
    let issuer_payload = json!({
        "iss": "https://example.com/issuer",
        "iat": 1683000000u64,
        "_sd_alg": "sha-256",
    });
    let issuer_signed_jwt = encode_signed_jwt_with_header_options(
        &issuer_payload,
        &issuer.jwk,
        &issuer.private,
        &JwtHeaderEncodeOptions::new(Some("id_token".to_owned())),
    )
    .expect("issuer JWT");
    let compact = serialize_sd_jwt_compact(&issuer_signed_jwt, &[]).expect("compact");

    let err = verify_sd_jwt(
        &compact,
        &issuer.jwk,
        &issuer.public,
        &SdJwtVerificationOptions::default(),
    )
    .expect_err("wrong issuer typ must fail");

    assert!(matches!(err, SdJwtEnvelopeError::Jwt));
}

#[test]
fn verify_sd_jwt_validates_key_binding_jwt() {
    let issuer = gen_ed25519();
    let holder = gen_ed25519();
    let disclosure =
        create_object_property_disclosure(
            "MDEyMzQ1Njc4OWFiY2RlZg",
            "given_name",
            json!("Max"),
        )
        .expect("disclosure");
    let digest =
        digest_disclosure(disclosure.encoded(), SdJwtHashAlgorithm::Sha256).expect("digest");
    let issuer_payload = json!({
        "iss": "https://example.com/issuer",
        "iat": 1683000000u64,
        "_sd": [digest],
        "_sd_alg": "sha-256",
    });
    let issuer_signed_jwt = encode_signed_jwt_with_header_options(
        &issuer_payload,
        &issuer.jwk,
        &issuer.private,
        &JwtHeaderEncodeOptions::new(Some("dc+sd-jwt".to_owned())),
    )
    .expect("issuer JWT");
    let disclosures = vec![disclosure.encoded().to_owned()];
    let compact_without_kb =
        serialize_sd_jwt_compact(&issuer_signed_jwt, &disclosures).expect("compact");
    let sd_hash = bytes_to_base64url(
        &hash_digest(HashAlgorithm::Sha2_256, compact_without_kb.as_bytes()).expect("hash"),
    );
    let kb_payload = json!({
        "sd_hash": sd_hash,
        "aud": "https://verifier.example",
        "nonce": "nonce-123",
        "iat": 1683000001u64,
        "exp": 1683000300u64,
    });
    let kb_jwt = encode_signed_jwt_with_header_options(
        &kb_payload,
        &holder.jwk,
        &holder.private,
        &JwtHeaderEncodeOptions::new(Some("kb+jwt".to_owned())),
    )
    .expect("KB JWT");
    let compact = format!("{compact_without_kb}{kb_jwt}");

    let unverified_error = verify_sd_jwt(
        &compact,
        &issuer.jwk,
        &issuer.public,
        &SdJwtVerificationOptions::default(),
    )
    .expect_err("a supplied KB-JWT must never be returned without verification");
    assert!(matches!(
        unverified_error,
        SdJwtEnvelopeError::InvalidKeyBindingJwt
    ));

    let mut missing_iat_payload = kb_payload.clone();
    missing_iat_payload
        .as_object_mut()
        .expect("KB-JWT payload is an object")
        .remove("iat");
    let missing_iat_jwt = encode_signed_jwt_with_header_options(
        &missing_iat_payload,
        &holder.jwk,
        &holder.private,
        &JwtHeaderEncodeOptions::new(Some("kb+jwt".to_owned())),
    )
    .expect("missing-iat KB JWT fixture");
    let missing_iat_compact = format!("{compact_without_kb}{missing_iat_jwt}");
    let missing_iat_error = verify_sd_jwt(
        &missing_iat_compact,
        &issuer.jwk,
        &issuer.public,
        &SdJwtVerificationOptions {
            require_key_binding: true,
            key_binding: Some(KeyBindingVerificationOptions {
                holder_jwk: &holder.jwk,
                holder_public_key: &holder.public,
                expected_audience: "https://verifier.example",
                expected_nonce: "nonce-123",
                now_unix: 1_683_000_002,
                max_future_iat_skew_seconds: 300,
                max_iat_age_seconds: 300,
            }),
            ..SdJwtVerificationOptions::default()
        },
    )
    .expect_err("RFC 9901 requires KB-JWT iat");
    assert!(matches!(
        missing_iat_error,
        SdJwtEnvelopeError::Jwt
    ));

    let mut epoch_iat_payload = kb_payload.clone();
    epoch_iat_payload["iat"] = json!(0u64);
    let epoch_iat_jwt = encode_signed_jwt_with_header_options(
        &epoch_iat_payload,
        &holder.jwk,
        &holder.private,
        &JwtHeaderEncodeOptions::new(Some("kb+jwt".to_owned())),
    )
    .expect("epoch-iat KB JWT fixture");
    let epoch_iat_compact = format!("{compact_without_kb}{epoch_iat_jwt}");
    let epoch_evaluation_error = verify_sd_jwt(
        &epoch_iat_compact,
        &issuer.jwk,
        &issuer.public,
        &SdJwtVerificationOptions {
            require_key_binding: true,
            key_binding: Some(KeyBindingVerificationOptions {
                holder_jwk: &holder.jwk,
                holder_public_key: &holder.public,
                expected_audience: "https://verifier.example",
                expected_nonce: "nonce-123",
                now_unix: 0,
                max_future_iat_skew_seconds: 300,
                max_iat_age_seconds: 300,
            }),
            ..SdJwtVerificationOptions::default()
        },
    )
    .expect_err("epoch-zero evaluation time must not disable freshness checks");
    assert!(matches!(
        epoch_evaluation_error,
        SdJwtEnvelopeError::InvalidKeyBindingJwt
    ));

    let verified = verify_sd_jwt(
        &compact,
        &issuer.jwk,
        &issuer.public,
        &SdJwtVerificationOptions {
            require_key_binding: true,
            key_binding: Some(KeyBindingVerificationOptions {
                holder_jwk: &holder.jwk,
                holder_public_key: &holder.public,
                expected_audience: "https://verifier.example",
                expected_nonce: "nonce-123",
                now_unix: 1683000002u64,
                max_future_iat_skew_seconds: 60,
                max_iat_age_seconds: 300,
            }),
            ..SdJwtVerificationOptions::default()
        },
    )
    .expect("verified SD-JWT+KB");

    assert_eq!(verified.key_binding_jwt, Some(kb_jwt));
    assert_eq!(verified.key_binding_payload, Some(kb_payload));
}

#[test]
fn verify_sd_jwt_enforces_issuer_confirmation_key_binding() {
    let issuer = gen_ed25519();
    let holder = gen_ed25519();
    let attacker = gen_ed25519();
    let issuer_payload = json!({
        "iss": "https://example.com/issuer",
        "iat": 1_683_000_000u64,
        "_sd_alg": "sha-256",
        "cnf": { "jwk": holder.jwk },
    });
    let issuer_signed_jwt = encode_signed_jwt_with_header_options(
        &issuer_payload,
        &issuer.jwk,
        &issuer.private,
        &JwtHeaderEncodeOptions::new(Some("dc+sd-jwt".to_owned())),
    )
    .expect("issuer JWT");
    let compact_without_kb =
        serialize_sd_jwt_compact(&issuer_signed_jwt, &[]).expect("compact");

    let stripped_error = verify_sd_jwt(
        &compact_without_kb,
        &issuer.jwk,
        &issuer.public,
        &SdJwtVerificationOptions::default(),
    )
    .expect_err("issuer-signed cnf must not be demoted to bearer verification");
    assert!(matches!(
        stripped_error,
        SdJwtEnvelopeError::InvalidKeyBindingJwt
    ));

    let holder_kb_jwt = build_key_binding_jwt(
        &issuer_signed_jwt,
        &[],
        &KeyBindingJwtBuildOptions {
            holder_jwk: &holder.jwk,
            holder_private_key: &holder.private,
            audience: "https://verifier.example",
            nonce: "nonce-123",
            issued_at_unix: 1_683_000_001,
        },
    )
    .expect("holder KB JWT fixture");
    let holder_bound = format!("{compact_without_kb}{holder_kb_jwt}");
    verify_sd_jwt(
        &holder_bound,
        &issuer.jwk,
        &issuer.public,
        &SdJwtVerificationOptions {
            require_key_binding: true,
            key_binding: Some(KeyBindingVerificationOptions {
                holder_jwk: &holder.jwk,
                holder_public_key: &holder.public,
                expected_audience: "https://verifier.example",
                expected_nonce: "nonce-123",
                now_unix: 1_683_000_002,
                max_future_iat_skew_seconds: 60,
                max_iat_age_seconds: 300,
            }),
            ..SdJwtVerificationOptions::default()
        },
    )
    .expect("matching issuer confirmation key must verify");

    let mut wrong_curve_payload = issuer_payload.clone();
    wrong_curve_payload["cnf"]["jwk"]["crv"] = Value::String("X25519".to_owned());
    let wrong_curve_issuer_jwt = encode_signed_jwt_with_header_options(
        &wrong_curve_payload,
        &issuer.jwk,
        &issuer.private,
        &JwtHeaderEncodeOptions::new(Some("dc+sd-jwt".to_owned())),
    )
    .expect("issuer JWT with mismatched confirmation curve");
    let wrong_curve_compact =
        serialize_sd_jwt_compact(&wrong_curve_issuer_jwt, &[]).expect("compact");
    let wrong_curve_kb_jwt = build_key_binding_jwt(
        &wrong_curve_issuer_jwt,
        &[],
        &KeyBindingJwtBuildOptions {
            holder_jwk: &holder.jwk,
            holder_private_key: &holder.private,
            audience: "https://verifier.example",
            nonce: "nonce-123",
            issued_at_unix: 1_683_000_001,
        },
    )
    .expect("holder KB JWT fixture");
    let wrong_curve_bound = format!("{wrong_curve_compact}{wrong_curve_kb_jwt}");
    assert!(matches!(
        verify_sd_jwt(
            &wrong_curve_bound,
            &issuer.jwk,
            &issuer.public,
            &SdJwtVerificationOptions {
                require_key_binding: true,
                key_binding: Some(KeyBindingVerificationOptions {
                    holder_jwk: &holder.jwk,
                    holder_public_key: &holder.public,
                    expected_audience: "https://verifier.example",
                    expected_nonce: "nonce-123",
                    now_unix: 1_683_000_002,
                    max_future_iat_skew_seconds: 60,
                    max_iat_age_seconds: 300,
                }),
                ..SdJwtVerificationOptions::default()
            },
        ),
        Err(SdJwtEnvelopeError::InvalidKeyBindingJwt)
    ));

    let attacker_kb_jwt = build_key_binding_jwt(
        &issuer_signed_jwt,
        &[],
        &KeyBindingJwtBuildOptions {
            holder_jwk: &attacker.jwk,
            holder_private_key: &attacker.private,
            audience: "https://verifier.example",
            nonce: "nonce-123",
            issued_at_unix: 1_683_000_001,
        },
    )
    .expect("attacker KB JWT fixture");
    let substituted = format!("{compact_without_kb}{attacker_kb_jwt}");
    let substituted_error = verify_sd_jwt(
        &substituted,
        &issuer.jwk,
        &issuer.public,
        &SdJwtVerificationOptions {
            require_key_binding: true,
            key_binding: Some(KeyBindingVerificationOptions {
                holder_jwk: &attacker.jwk,
                holder_public_key: &attacker.public,
                expected_audience: "https://verifier.example",
                expected_nonce: "nonce-123",
                now_unix: 1_683_000_002,
                max_future_iat_skew_seconds: 60,
                max_iat_age_seconds: 300,
            }),
            ..SdJwtVerificationOptions::default()
        },
    )
    .expect_err("KB-JWT key must match issuer-signed cnf.jwk");
    assert!(matches!(
        substituted_error,
        SdJwtEnvelopeError::InvalidKeyBindingJwt
    ));
}

#[test]
fn build_key_binding_jwt_builds_verifiable_kb_jwt() {
    let issuer = gen_ed25519();
    let holder = gen_ed25519();
    let disclosure =
        create_object_property_disclosure(
            "MDEyMzQ1Njc4OWFiY2RlZg",
            "given_name",
            json!("Max"),
        )
        .expect("disclosure");
    let digest =
        digest_disclosure(disclosure.encoded(), SdJwtHashAlgorithm::Sha256).expect("digest");
    let issuer_payload = json!({
        "iss": "https://example.com/issuer",
        "iat": 1683000000u64,
        "_sd": [digest],
        "_sd_alg": "sha-256",
    });
    let issuer_signed_jwt = encode_signed_jwt_with_header_options(
        &issuer_payload,
        &issuer.jwk,
        &issuer.private,
        &JwtHeaderEncodeOptions::new(Some("dc+sd-jwt".to_owned())),
    )
    .expect("issuer JWT");
    let disclosures = vec![disclosure.encoded().to_owned()];
    let kb_jwt = build_key_binding_jwt(
        &issuer_signed_jwt,
        &disclosures,
        &KeyBindingJwtBuildOptions {
            holder_jwk: &holder.jwk,
            holder_private_key: &holder.private,
            audience: "https://verifier.example",
            nonce: "nonce-123",
            issued_at_unix: 1_683_000_001,
        },
    )
    .expect("KB JWT");
    let compact_without_kb =
        serialize_sd_jwt_compact(&issuer_signed_jwt, &disclosures).expect("compact");
    let compact = format!("{compact_without_kb}{kb_jwt}");

    let verified = verify_sd_jwt(
        &compact,
        &issuer.jwk,
        &issuer.public,
        &SdJwtVerificationOptions {
            require_key_binding: true,
            key_binding: Some(KeyBindingVerificationOptions {
                holder_jwk: &holder.jwk,
                holder_public_key: &holder.public,
                expected_audience: "https://verifier.example",
                expected_nonce: "nonce-123",
                now_unix: 1_683_000_002,
                max_future_iat_skew_seconds: 60,
                max_iat_age_seconds: 300,
            }),
            ..SdJwtVerificationOptions::default()
        },
    )
    .expect("verified SD-JWT+KB");

    assert_eq!(verified.key_binding_jwt, Some(kb_jwt));
    let payload = verified
        .key_binding_payload
        .as_ref()
        .and_then(Value::as_object)
        .expect("verified KB-JWT payload is an object");
    assert_eq!(
        payload.keys().map(String::as_str).collect::<BTreeSet<_>>(),
        BTreeSet::from(["aud", "iat", "nonce", "sd_hash"])
    );
    assert_eq!(
        verified
            .key_binding_payload
            .as_ref()
            .and_then(|payload| payload.get("nonce"))
            .and_then(Value::as_str),
        Some("nonce-123")
    );

    let excessive_future_skew = verify_sd_jwt(
        &compact,
        &issuer.jwk,
        &issuer.public,
        &SdJwtVerificationOptions {
            require_key_binding: true,
            key_binding: Some(KeyBindingVerificationOptions {
                holder_jwk: &holder.jwk,
                holder_public_key: &holder.public,
                expected_audience: "https://verifier.example",
                expected_nonce: "nonce-123",
                now_unix: 1_683_000_002,
                max_future_iat_skew_seconds: 301,
                max_iat_age_seconds: 300,
            }),
            ..SdJwtVerificationOptions::default()
        },
    )
    .expect_err("future iat skew above the security ceiling must fail");
    assert!(matches!(
        excessive_future_skew,
        SdJwtEnvelopeError::InvalidKeyBindingJwt
    ));
}

#[test]
fn verify_sd_jwt_rejects_wrong_key_binding_nonce() {
    let issuer = gen_ed25519();
    let holder = gen_ed25519();
    let issuer_payload = json!({
        "iss": "https://example.com/issuer",
        "iat": 1683000000u64,
        "_sd_alg": "sha-256",
    });
    let issuer_signed_jwt = encode_signed_jwt_with_header_options(
        &issuer_payload,
        &issuer.jwk,
        &issuer.private,
        &JwtHeaderEncodeOptions::new(Some("dc+sd-jwt".to_owned())),
    )
    .expect("issuer JWT");
    let compact_without_kb = serialize_sd_jwt_compact(&issuer_signed_jwt, &[]).expect("compact");
    let sd_hash = bytes_to_base64url(
        &hash_digest(HashAlgorithm::Sha2_256, compact_without_kb.as_bytes()).expect("hash"),
    );
    let kb_payload = json!({
        "sd_hash": sd_hash,
        "aud": "https://verifier.example",
        "nonce": "nonce-123",
        "iat": 1683000001u64,
        "exp": 1683000300u64,
    });
    let kb_jwt = encode_signed_jwt_with_header_options(
        &kb_payload,
        &holder.jwk,
        &holder.private,
        &JwtHeaderEncodeOptions::new(Some("kb+jwt".to_owned())),
    )
    .expect("KB JWT");
    let compact = format!("{compact_without_kb}{kb_jwt}");

    let err = verify_sd_jwt(
        &compact,
        &issuer.jwk,
        &issuer.public,
        &SdJwtVerificationOptions {
            require_key_binding: true,
            key_binding: Some(KeyBindingVerificationOptions {
                holder_jwk: &holder.jwk,
                holder_public_key: &holder.public,
                expected_audience: "https://verifier.example",
                expected_nonce: "different-nonce",
                now_unix: 1683000002u64,
                max_future_iat_skew_seconds: 60,
                max_iat_age_seconds: 300,
            }),
            ..SdJwtVerificationOptions::default()
        },
    )
    .expect_err("wrong nonce must fail");

    assert!(matches!(err, SdJwtEnvelopeError::InvalidKeyBindingJwt));
}

#[test]
fn verify_sd_jwt_rejects_wrong_key_binding_sd_hash() {
    let issuer = gen_ed25519();
    let holder = gen_ed25519();
    let issuer_payload = json!({
        "iss": "https://example.com/issuer",
        "iat": 1683000000u64,
        "_sd_alg": "sha-256",
    });
    let issuer_signed_jwt = encode_signed_jwt_with_header_options(
        &issuer_payload,
        &issuer.jwk,
        &issuer.private,
        &JwtHeaderEncodeOptions::new(Some("dc+sd-jwt".to_owned())),
    )
    .expect("issuer JWT");
    let compact_without_kb = serialize_sd_jwt_compact(&issuer_signed_jwt, &[]).expect("compact");
    let kb_payload = json!({
        "sd_hash": "not-the-presented-sd-jwt",
        "aud": "https://verifier.example",
        "nonce": "nonce-123",
        "iat": 1683000001u64,
        "exp": 1683000300u64,
    });
    let kb_jwt = encode_signed_jwt_with_header_options(
        &kb_payload,
        &holder.jwk,
        &holder.private,
        &JwtHeaderEncodeOptions::new(Some("kb+jwt".to_owned())),
    )
    .expect("KB JWT");
    let compact = format!("{compact_without_kb}{kb_jwt}");

    let err = verify_sd_jwt(
        &compact,
        &issuer.jwk,
        &issuer.public,
        &SdJwtVerificationOptions {
            require_key_binding: true,
            key_binding: Some(KeyBindingVerificationOptions {
                holder_jwk: &holder.jwk,
                holder_public_key: &holder.public,
                expected_audience: "https://verifier.example",
                expected_nonce: "nonce-123",
                now_unix: 1683000002u64,
                max_future_iat_skew_seconds: 60,
                max_iat_age_seconds: 300,
            }),
            ..SdJwtVerificationOptions::default()
        },
    )
    .expect_err("wrong sd_hash must fail");

    assert!(matches!(err, SdJwtEnvelopeError::InvalidKeyBindingJwt));
}

#[test]
fn verify_sd_jwt_rejects_missing_required_key_binding() {
    let issuer = gen_ed25519();
    let issuer_payload = json!({
        "iss": "https://example.com/issuer",
        "iat": 1683000000u64,
        "_sd_alg": "sha-256",
    });
    let issuer_signed_jwt = encode_signed_jwt_with_header_options(
        &issuer_payload,
        &issuer.jwk,
        &issuer.private,
        &JwtHeaderEncodeOptions::new(Some("dc+sd-jwt".to_owned())),
    )
    .expect("issuer JWT");
    let compact = serialize_sd_jwt_compact(&issuer_signed_jwt, &[]).expect("compact");

    let err = verify_sd_jwt(
        &compact,
        &issuer.jwk,
        &issuer.public,
        &SdJwtVerificationOptions {
            require_key_binding: true,
            ..SdJwtVerificationOptions::default()
        },
    )
    .expect_err("missing required KB-JWT must fail");

    assert!(matches!(err, SdJwtEnvelopeError::InvalidKeyBindingJwt));
}

#[test]
fn process_sd_jwt_payload_rejects_unmatched_disclosure() {
    let disclosure = create_object_property_disclosure(
        "MDEyMzQ1Njc4OWFiY2RlZg",
        "name",
        json!("value"),
    )
        .expect("valid disclosure must encode");
    let err = process_sd_jwt_payload(
        json!({"iss": "issuer", "_sd_alg": "sha-256"}),
        &[disclosure.encoded().to_owned()],
        SdJwtProcessingPolicy::default(),
    )
    .expect_err("unmatched disclosure must fail");

    assert!(matches!(err, SdJwtEnvelopeError::UnmatchedDisclosure));
}

#[test]
fn process_sd_jwt_payload_rejects_duplicate_digests() {
    let err = process_sd_jwt_payload(
        json!({"_sd": ["same", "same"], "_sd_alg": "sha-256"}),
        &[],
        SdJwtProcessingPolicy::default(),
    )
    .expect_err("duplicate digests must fail closed");

    assert!(matches!(err, SdJwtEnvelopeError::DuplicateDigest));
}

#[test]
fn process_sd_jwt_payload_rejects_malicious_depth() {
    let err = process_sd_jwt_payload(
        json!({"nested": {"nested": {"nested": true}}}),
        &[],
        SdJwtProcessingPolicy {
            max_depth: 1,
            max_nodes: 16,
        },
    )
    .expect_err("oversized recursive payload must fail closed");

    assert!(matches!(err, SdJwtEnvelopeError::ProcessingDepthExceeded));
}
