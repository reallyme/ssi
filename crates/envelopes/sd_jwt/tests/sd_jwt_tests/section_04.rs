// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#[test]
fn key_binding_build_options_debug_redacts_private_material() {
    let holder = gen_ed25519();
    let options = KeyBindingJwtBuildOptions {
        holder_jwk: &holder.jwk,
        holder_private_key: &[222, 173, 190, 239],
        audience: "https://verifier.example",
        nonce: "nonce-123",
        issued_at_unix: VERIFY_NOW_UNIX,
    };

    assert_eq!(format!("{options:?}"), "KeyBindingJwtBuildOptions([REDACTED])");
}

const REGRESSION_SALT: &str = "MDEyMzQ1Njc4OWFiY2RlZg";

fn sign_dc_sd_jwt(issuer: &TestKey, payload: &Value, disclosures: &[String]) -> String {
    let mut payload = payload.clone();
    if let Some(object) = payload.as_object_mut() {
        object
            .entry("vct")
            .or_insert_with(|| Value::String("urn:example:test".to_owned()));
    }
    let issuer_signed_jwt = encode_signed_jwt_with_header_options(
        &payload,
        &issuer.jwk,
        &issuer.private,
        &JwtHeaderEncodeOptions::new(Some("dc+sd-jwt".to_owned())),
    )
    .expect("issuer JWT");
    serialize_sd_jwt_compact(&issuer_signed_jwt, disclosures).expect("compact SD-JWT")
}

fn verify_with_clock(issuer: &TestKey, compact: &str, now_unix: u64) -> SdJwtEnvelopeError {
    verify_sd_jwt(
        compact,
        &issuer.jwk,
        &issuer.public,
        &SdJwtVerificationOptions::new(now_unix),
    )
    .expect_err("verification must fail")
}

fn object_disclosure(name: &str, value: Value) -> (String, String) {
    let disclosure =
        create_object_property_disclosure(REGRESSION_SALT, name, value).expect("disclosure");
    let digest =
        digest_disclosure(disclosure.encoded(), SdJwtHashAlgorithm::Sha256).expect("digest");
    (disclosure.encoded().to_owned(), digest)
}

#[test]
fn verify_sd_jwt_enforces_credential_validity_window() {
    let issuer = gen_ed25519();
    let now = 1_700_000_000_u64;
    let window = json!({
        "iss": "https://issuer.example",
        "iat": now - 100,
        "nbf": now - 100,
        "exp": now + 100,
    });
    let valid = sign_dc_sd_jwt(&issuer, &window, &[]);
    verify_sd_jwt(
        &valid,
        &issuer.jwk,
        &issuer.public,
        &SdJwtVerificationOptions::new(now),
    )
    .expect("credential inside its validity window verifies");

    assert_eq!(
        verify_with_clock(&issuer, &valid, now + 100 + DEFAULT_SD_JWT_CLOCK_SKEW_SECONDS),
        SdJwtEnvelopeError::CredentialExpired
    );
    assert_eq!(
        verify_with_clock(&issuer, &valid, now - 101 - DEFAULT_SD_JWT_CLOCK_SKEW_SECONDS),
        SdJwtEnvelopeError::CredentialNotYetValid
    );

    let future_iat = sign_dc_sd_jwt(
        &issuer,
        &json!({"iss": "https://issuer.example", "iat": now + 3_600}),
        &[],
    );
    assert_eq!(
        verify_with_clock(&issuer, &future_iat, now),
        SdJwtEnvelopeError::InvalidTemporalClaim
    );

    let malformed_exp = serialize_sd_jwt_compact(
        &sign_unvalidated_ed25519_jwt(
            &json!({"iss": "https://issuer.example", "vct": "urn:example:test", "exp": "tomorrow"}),
            &issuer,
            "dc+sd-jwt",
        ),
        &[],
    )
    .expect("malformed-exp compact SD-JWT");
    assert_eq!(
        verify_with_clock(&issuer, &malformed_exp, now),
        SdJwtEnvelopeError::InvalidTemporalClaim
    );

    let inverted = serialize_sd_jwt_compact(
        &sign_unvalidated_ed25519_jwt(
            &json!({"iss": "https://issuer.example", "vct": "urn:example:test", "nbf": now + 10, "exp": now + 10}),
            &issuer,
            "dc+sd-jwt",
        ),
        &[],
    )
    .expect("inverted-window compact SD-JWT");
    assert_eq!(
        verify_with_clock(&issuer, &inverted, now),
        SdJwtEnvelopeError::InvalidTemporalClaim
    );
}

#[test]
fn verify_sd_jwt_rejects_missing_exp_when_the_policy_requires_expiration() {
    let issuer = gen_ed25519();
    let now = 1_700_000_000_u64;
    let compact = sign_dc_sd_jwt(
        &issuer,
        &json!({"iss": "https://issuer.example", "iat": now}),
        &[],
    );
    let options = SdJwtVerificationOptions {
        require_exp: true,
        ..SdJwtVerificationOptions::new(now)
    };

    assert_eq!(
        verify_sd_jwt(&compact, &issuer.jwk, &issuer.public, &options),
        Err(SdJwtEnvelopeError::InvalidTemporalClaim)
    );
}

#[test]
fn verify_sd_jwt_reads_selectively_disclosed_iat() {
    let issuer = gen_ed25519();
    let now = 1_700_000_000_u64;
    let (encoded, digest) = object_disclosure("iat", json!(now + 3_600));
    let compact = sign_dc_sd_jwt(
        &issuer,
        &json!({"iss": "https://issuer.example", "_sd": [digest], "_sd_alg": "sha-256"}),
        &[encoded],
    );
    assert_eq!(
        verify_with_clock(&issuer, &compact, now),
        SdJwtEnvelopeError::InvalidTemporalClaim
    );
}

#[test]
fn verify_sd_jwt_rejects_unset_or_unbounded_clock_policy() {
    let issuer = gen_ed25519();
    let compact = sign_dc_sd_jwt(&issuer, &json!({"iss": "https://issuer.example"}), &[]);
    assert_eq!(
        verify_with_clock(&issuer, &compact, 0),
        SdJwtEnvelopeError::InvalidVerificationPolicy
    );
    let unbounded_skew = SdJwtVerificationOptions {
        clock_skew_seconds: MAX_SD_JWT_CLOCK_SKEW_SECONDS + 1,
        ..SdJwtVerificationOptions::new(VERIFY_NOW_UNIX)
    };
    assert_eq!(
        verify_sd_jwt(&compact, &issuer.jwk, &issuer.public, &unbounded_skew).err(),
        Some(SdJwtEnvelopeError::InvalidVerificationPolicy)
    );
}

#[test]
fn verify_sd_jwt_rejects_empty_key_binding_expectations_before_signature_work() {
    let issuer = gen_ed25519();
    let holder = gen_ed25519();
    // A syntactically valid but unsigned credential proves the policy check
    // runs before any issuer signature verification.
    let compact = "e30.e30.c2ln~";
    for (audience, nonce) in [("", "nonce-123"), ("https://verifier.example", "")] {
        let options = SdJwtVerificationOptions {
            require_key_binding: true,
            key_binding: Some(KeyBindingVerificationOptions {
                holder_jwk: &holder.jwk,
                holder_public_key: &holder.public,
                expected_audience: audience,
                expected_nonce: nonce,
                now_unix: VERIFY_NOW_UNIX,
                max_future_iat_skew_seconds: 60,
                max_iat_age_seconds: 300,
            }),
            ..SdJwtVerificationOptions::new(VERIFY_NOW_UNIX)
        };
        assert_eq!(
            verify_sd_jwt(compact, &issuer.jwk, &issuer.public, &options).err(),
            Some(SdJwtEnvelopeError::InvalidKeyBindingJwt)
        );
    }
}

#[test]
fn key_binding_verification_options_enforce_every_policy_boundary() {
    let holder = gen_ed25519();
    let valid = KeyBindingVerificationOptions {
        holder_jwk: &holder.jwk,
        holder_public_key: &holder.public,
        expected_audience: "https://verifier.example",
        expected_nonce: "nonce-123",
        now_unix: VERIFY_NOW_UNIX,
        max_future_iat_skew_seconds: MAX_KB_JWT_FUTURE_IAT_SKEW_SECONDS,
        max_iat_age_seconds: MAX_KB_JWT_AGE_SECONDS,
    };
    assert_eq!(valid.validate(), Ok(()));

    for invalid in [
        KeyBindingVerificationOptions {
            expected_audience: "",
            ..valid
        },
        KeyBindingVerificationOptions {
            expected_nonce: "",
            ..valid
        },
        KeyBindingVerificationOptions {
            now_unix: 0,
            ..valid
        },
        KeyBindingVerificationOptions {
            max_future_iat_skew_seconds: MAX_KB_JWT_FUTURE_IAT_SKEW_SECONDS + 1,
            ..valid
        },
        KeyBindingVerificationOptions {
            max_iat_age_seconds: 0,
            ..valid
        },
        KeyBindingVerificationOptions {
            max_iat_age_seconds: MAX_KB_JWT_AGE_SECONDS + 1,
            ..valid
        },
    ] {
        assert_eq!(
            invalid.validate(),
            Err(SdJwtEnvelopeError::InvalidKeyBindingJwt)
        );
    }
}

#[test]
fn issuance_keeps_registered_claims_in_the_issuer_payload() {
    let issuer = gen_ed25519();
    let holder = gen_ed25519();
    let claims = json!({
        "iss": "https://issuer.example",
        "vct": "urn:example:credential",
        "exp": 1_900_000_000_u64,
        "nbf": 1_600_000_000_u64,
        "cnf": {"jwk": holder.jwk},
        "status": {"status_list": {"idx": 7, "uri": "https://issuer.example/status"}},
        "given_name": "Max",
    });
    for strategy in [
        SdJwtDisclosureStrategy::TopLevel,
        SdJwtDisclosureStrategy::AllLevels,
    ] {
        let mut salts = DeterministicSaltSource::new();
        let issued = issue_sd_jwt(
            SdJwtIssuanceInput {
                claims: claims.clone(),
                issuer_jwk: &issuer.jwk,
                issuer_private_key: &issuer.private,
                policy: SdJwtIssuancePolicy {
                    disclosure_strategy: strategy,
                    ..SdJwtIssuancePolicy::default()
                },
            },
            &mut salts,
        )
        .expect("issuance succeeds");
        for name in ["iss", "vct", "exp", "nbf", "cnf", "status"] {
            assert_eq!(
                issued.issuer_payload.get(name),
                claims.get(name),
                "{name} must stay verbatim in the issuer payload"
            );
        }
        assert!(issued.issuer_payload.get("given_name").is_none());
    }
}

#[test]
fn issuance_rejects_explicit_paths_into_registered_claims() {
    let issuer = gen_ed25519();
    for path in ["$.cnf", "$.cnf.jwk", "$.status", "$.exp", "$.vct#integrity"] {
        let mut salts = DeterministicSaltSource::new();
        let error = issue_sd_jwt(
            SdJwtIssuanceInput {
                claims: json!({
                    "iss": "https://issuer.example",
                    "vct": "https://issuer.example/credentials/example",
                    "cnf": {"jwk": {}}
                }),
                issuer_jwk: &issuer.jwk,
                issuer_private_key: &issuer.private,
                policy: SdJwtIssuancePolicy {
                    disclosure_strategy: SdJwtDisclosureStrategy::JsonPaths(BTreeSet::from([
                        path.to_owned(),
                    ])),
                    ..SdJwtIssuancePolicy::default()
                },
            },
            &mut salts,
        )
        .expect_err("registered claims must not become disclosable");
        assert_eq!(error, SdJwtEnvelopeError::NonSelectivelyDisclosableClaim);
    }
}

#[test]
fn processing_rejects_top_level_disclosure_of_registered_claims() {
    for name in ["iss", "nbf", "exp", "cnf", "vct", "vct#integrity", "status"] {
        let (encoded, digest) = object_disclosure(name, json!("value"));
        let error = process_sd_jwt_payload(
            json!({"_sd": [digest], "_sd_alg": "sha-256"}),
            &[encoded],
            SdJwtProcessingPolicy::default(),
        )
        .expect_err("registered claims must not be disclosed at top level");
        assert_eq!(error, SdJwtEnvelopeError::NonSelectivelyDisclosableClaim);
    }

    let (encoded, digest) = object_disclosure("exp", json!("nested value"));
    let resolved = process_sd_jwt_payload(
        json!({"passport": {"_sd": [digest]}}),
        &[encoded],
        SdJwtProcessingPolicy::default(),
    )
    .expect("nested members with registered names are ordinary claims");
    assert_eq!(resolved, json!({"passport": {"exp": "nested value"}}));
}

#[test]
fn verify_sd_jwt_rejects_stripped_disclosable_confirmation_key() {
    let issuer = gen_ed25519();
    let holder = gen_ed25519();
    let (encoded, digest) = object_disclosure("cnf", json!({"jwk": holder.jwk}));
    let payload = json!({"iss": "https://issuer.example", "_sd": [digest], "_sd_alg": "sha-256"});
    let with_cnf = sign_dc_sd_jwt(&issuer, &payload, &[encoded]);
    assert_eq!(
        verify_with_clock(&issuer, &with_cnf, VERIFY_NOW_UNIX),
        SdJwtEnvelopeError::NonSelectivelyDisclosableClaim
    );
}

#[test]
fn processing_rejects_disclosure_kind_mismatch_and_misplaced_reserved_members() {
    let element = create_array_element_disclosure(REGRESSION_SALT, json!("DE")).expect("element");
    let element_digest =
        digest_disclosure(element.encoded(), SdJwtHashAlgorithm::Sha256).expect("digest");
    assert_eq!(
        process_sd_jwt_payload(
            json!({"_sd": [element_digest.clone()]}),
            &[element.encoded().to_owned()],
            SdJwtProcessingPolicy::default(),
        )
        .err(),
        Some(SdJwtEnvelopeError::InvalidDisclosureFormat)
    );

    assert_eq!(
        process_sd_jwt_payload(
            json!({"nationality": {"...": element_digest}}),
            &[element.encoded().to_owned()],
            SdJwtProcessingPolicy::default(),
        )
        .err(),
        Some(SdJwtEnvelopeError::InvalidReservedClaimPlacement)
    );

    let (nested_alg, nested_alg_digest) =
        object_disclosure("address", json!({"_sd_alg": "sha-256", "locality": "Berlin"}));
    assert_eq!(
        process_sd_jwt_payload(
            json!({"_sd": [nested_alg_digest]}),
            &[nested_alg],
            SdJwtProcessingPolicy::default(),
        )
        .err(),
        Some(SdJwtEnvelopeError::InvalidReservedClaimPlacement)
    );

    let (misplaced_placeholder, misplaced_digest) =
        object_disclosure("address", json!({"...": "digest", "locality": "Berlin"}));
    assert_eq!(
        process_sd_jwt_payload(
            json!({"_sd": [misplaced_digest]}),
            &[misplaced_placeholder],
            SdJwtProcessingPolicy::default(),
        )
        .err(),
        Some(SdJwtEnvelopeError::InvalidReservedClaimPlacement)
    );

    assert_eq!(
        create_object_property_disclosure(REGRESSION_SALT, "_sd_alg", json!("sha-256")).err(),
        Some(SdJwtEnvelopeError::InvalidDisclosureClaimName)
    );
}

#[test]
fn processing_policy_is_clamped_to_hard_ceilings() {
    let mut deep = json!("leaf");
    for _ in 0..(reallyme_sd_jwt::MAX_SD_JWT_PROCESSING_DEPTH + 8) {
        deep = json!([deep]);
    }
    let error = process_sd_jwt_payload(
        json!({"deep": deep}),
        &[],
        SdJwtProcessingPolicy {
            max_depth: usize::MAX,
            max_nodes: usize::MAX,
        },
    )
    .expect_err("caller policy cannot lift the hard depth ceiling");
    assert_eq!(error, SdJwtEnvelopeError::ProcessingDepthExceeded);
}

#[test]
fn disclosure_selection_bounds_requested_paths_and_components() {
    let too_many_paths = vec![
        vec![SdJwtClaimPathComponent::Name("claim".to_owned())];
        MAX_REQUESTED_SD_JWT_PATHS + 1
    ];
    assert_eq!(
        select_sd_jwt_disclosures(
            &json!({}),
            &[],
            &too_many_paths,
            SdJwtProcessingPolicy::default(),
        )
        .err(),
        Some(SdJwtEnvelopeError::InvalidIssuanceInput)
    );

    let too_deep_path = vec![vec![
        SdJwtClaimPathComponent::All;
        MAX_REQUESTED_SD_JWT_PATH_COMPONENTS + 1
    ]];
    assert_eq!(
        select_sd_jwt_disclosures(
            &json!({}),
            &[],
            &too_deep_path,
            SdJwtProcessingPolicy::default(),
        )
        .err(),
        Some(SdJwtEnvelopeError::InvalidIssuanceInput)
    );

    let oversized_name = vec![vec![SdJwtClaimPathComponent::Name(
        "x".repeat(MAX_REQUESTED_SD_JWT_PATH_NAME_BYTES + 1),
    )]];
    assert_eq!(
        select_sd_jwt_disclosures(
            &json!({}),
            &[],
            &oversized_name,
            SdJwtProcessingPolicy::default(),
        )
        .err(),
        Some(SdJwtEnvelopeError::InvalidIssuanceInput)
    );
}

#[test]
fn json_serialization_rejects_whitespace_and_duplicate_members() {
    let issuer = gen_ed25519();
    let compact = sign_dc_sd_jwt(&issuer, &json!({"iss": "https://issuer.example"}), &[]);
    let jwt = compact.trim_end_matches('~');
    let mut parts = jwt.split('.');
    let protected = parts.next().expect("protected");
    let payload = parts.next().expect("payload");
    let signature = parts.next().expect("signature");

    let valid = format!(
        r#"{{"payload":"{payload}","protected":"{protected}","signature":"{signature}"}}"#
    );
    parse_sd_jwt_json_serialization(&valid).expect("strict JSON serialization parses");

    let (head, tail) = signature.split_at(4);
    let whitespace = format!(
        r#"{{"payload":"{payload}","protected":"{protected}","signature":"{head} {tail}"}}"#
    );
    assert_eq!(
        parse_sd_jwt_json_serialization(&whitespace).err(),
        Some(SdJwtEnvelopeError::InvalidJsonSerialization)
    );

    let duplicate = format!(
        r#"{{"payload":"{payload}","protected":"{protected}","signature":"{signature}","signature":"{signature}"}}"#
    );
    assert_eq!(
        parse_sd_jwt_json_serialization(&duplicate).err(),
        Some(SdJwtEnvelopeError::InvalidJsonSerialization)
    );
}

#[test]
fn json_serialization_rejects_unprotected_crit() {
    let input = json!({
        "payload": "e30",
        "protected": "e30",
        "signature": "AA",
        "header": { "crit": ["example"] }
    });

    assert_eq!(
        parse_sd_jwt_json_serialization(&input.to_string()).err(),
        Some(SdJwtEnvelopeError::InvalidJsonSerialization)
    );
}

struct ZeroEntropySaltSource;

impl SdJwtSaltSource for ZeroEntropySaltSource {
    fn next_salt(&mut self) -> Result<String, SdJwtEnvelopeError> {
        Ok(REGRESSION_SALT.to_owned())
    }

    fn next_decoy_digest(&mut self) -> Result<String, SdJwtEnvelopeError> {
        Ok(bytes_to_base64url(&[0_u8; 32]))
    }
}

#[test]
fn array_decoys_are_not_pinned_to_the_end_of_the_array() {
    let issuer = gen_ed25519();
    let issued = issue_sd_jwt(
        SdJwtIssuanceInput {
            claims: json!({
                "iss": "https://issuer.example",
                "vct": "https://issuer.example/credentials/example",
                "roles": ["driver", "resident"]
            }),
            issuer_jwk: &issuer.jwk,
            issuer_private_key: &issuer.private,
            policy: SdJwtIssuancePolicy {
                disclosure_strategy: SdJwtDisclosureStrategy::None,
                decoys: DecoyPolicy {
                    object_decoys: 0,
                    array_decoys: 1,
                },
                ..SdJwtIssuancePolicy::default()
            },
        },
        &mut ZeroEntropySaltSource,
    )
    .expect("issuance succeeds");
    let roles = issued
        .issuer_payload
        .get("roles")
        .and_then(Value::as_array)
        .expect("roles array");
    assert_eq!(roles.len(), 3);
    assert_eq!(roles[0], json!({"...": bytes_to_base64url(&[0_u8; 32])}));
    assert_eq!(roles[1], json!("driver"));
    assert_eq!(roles[2], json!("resident"));
}

#[test]
fn receipt_and_stored_credential_policies_reject_missing_required_expiration() {
    let issuer = gen_ed25519();
    let holder = gen_ed25519();
    let issued = issue_receipt_credential(
        &issuer,
        serde_json::to_value(&holder.jwk).expect("holder JWK JSON"),
        json!(RECEIPT_NOW),
        None,
        None,
    );
    let mut receipt = receipt_policy(&holder, RECEIPT_NOW);
    receipt.require_exp = true;
    let mut credential = credential_policy(&holder, RECEIPT_NOW);
    credential.require_exp = true;

    assert_eq!(
        verify_sd_jwt_receipt(&issued.compact, &issuer.jwk, &issuer.public, &receipt).err(),
        Some(SdJwtEnvelopeError::InvalidReceiptTemporalClaim)
    );
    assert_eq!(
        verify_sd_jwt_credential(
            &issued.compact,
            &issuer.jwk,
            &issuer.public,
            &credential,
        )
        .err(),
        Some(SdJwtEnvelopeError::InvalidReceiptTemporalClaim)
    );
}
