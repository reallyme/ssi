// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

const RECEIPT_NOW: u64 = 1_800_000_000;
const RECEIPT_ISSUER: &str = "https://issuer.example";
const RECEIPT_VCT: &str = "urn:example:credential";

struct AcceptCredentialStatus;

impl reallyme_sd_jwt::SdJwtCredentialStatusVerifier for AcceptCredentialStatus {
    fn verify_status(
        &self,
        status: &Value,
        _now_unix: u64,
    ) -> Result<(), SdJwtEnvelopeError> {
        if status.get("status_list").is_some() {
            Ok(())
        } else {
            Err(SdJwtEnvelopeError::CredentialStatusNotVerified)
        }
    }
}

fn issue_receipt_credential(
    issuer: &TestKey,
    holder_jwk: Value,
    issued_at: Value,
    not_before: Option<Value>,
    expires_at: Option<Value>,
) -> reallyme_sd_jwt::IssuedSdJwt {
    issue_credential_with_registered_claims(
        issuer,
        Some(RECEIPT_ISSUER),
        holder_jwk,
        Some(issued_at),
        not_before,
        expires_at,
    )
}

#[test]
fn credential_status_claim_requires_an_injected_verifier() {
    let issuer = gen_p256();
    let holder = gen_p256();
    let mut salts = DeterministicSaltSource::new();
    let issued = issue_sd_jwt(
        SdJwtIssuanceInput {
            claims: json!({
                "iss": RECEIPT_ISSUER,
                "vct": RECEIPT_VCT,
                "iat": RECEIPT_NOW,
                "exp": RECEIPT_NOW + 600,
                "cnf": {"jwk": holder.jwk},
                "status": {"status_list": {"idx": 7, "uri": "https://issuer.example/status"}},
                "given_name": "ALICE",
            }),
            issuer_jwk: &issuer.jwk,
            issuer_private_key: &issuer.private,
            policy: SdJwtIssuancePolicy::default(),
        },
        &mut salts,
    )
    .expect("status credential issuance");

    let policy = credential_policy(&holder, RECEIPT_NOW);
    assert_eq!(
        verify_sd_jwt_credential(&issued.compact, &issuer.jwk, &issuer.public, &policy).err(),
        Some(SdJwtEnvelopeError::CredentialStatusNotVerified)
    );

    let verifier = AcceptCredentialStatus;
    let mut policy = credential_policy(&holder, RECEIPT_NOW);
    policy.status_verifier = Some(&verifier);
    assert!(verify_sd_jwt_credential(&issued.compact, &issuer.jwk, &issuer.public, &policy).is_ok());
}

fn issue_credential_with_registered_claims(
    issuer: &TestKey,
    issuer_claim: Option<&str>,
    holder_jwk: Value,
    issued_at: Option<Value>,
    not_before: Option<Value>,
    expires_at: Option<Value>,
) -> reallyme_sd_jwt::IssuedSdJwt {
    issue_credential_with_disclosure_policy(
        issuer,
        issuer_claim,
        holder_jwk,
        issued_at,
        not_before,
        expires_at,
        false,
    )
}

#[allow(clippy::too_many_arguments)]
fn issue_credential_with_disclosure_policy(
    issuer: &TestKey,
    issuer_claim: Option<&str>,
    holder_jwk: Value,
    issued_at: Option<Value>,
    not_before: Option<Value>,
    expires_at: Option<Value>,
    disclose_issued_at: bool,
) -> reallyme_sd_jwt::IssuedSdJwt {
    let mut claims = Map::new();
    if let Some(value) = issuer_claim {
        claims.insert("iss".to_owned(), Value::String(value.to_owned()));
    }
    claims.insert("vct".to_owned(), Value::String(RECEIPT_VCT.to_owned()));
    if let Some(value) = issued_at {
        claims.insert("iat".to_owned(), value);
    }
    claims.insert("cnf".to_owned(), json!({"jwk": holder_jwk}));
    claims.insert("given_name".to_owned(), Value::String("ALICE".to_owned()));
    if let Some(value) = not_before {
        claims.insert("nbf".to_owned(), value);
    }
    if let Some(value) = expires_at {
        claims.insert("exp".to_owned(), value);
    }
    let mut paths = BTreeSet::new();
    paths.insert("$.given_name".to_owned());
    if disclose_issued_at {
        paths.insert("$.iat".to_owned());
    }
    let mut salt_source = DeterministicSaltSource::new();
    issue_sd_jwt(
        SdJwtIssuanceInput {
            claims: Value::Object(claims),
            issuer_jwk: &issuer.jwk,
            issuer_private_key: &issuer.private,
            policy: SdJwtIssuancePolicy {
                disclosure_strategy: SdJwtDisclosureStrategy::JsonPaths(paths),
                decoys: DecoyPolicy::none(),
                issuer_type: reallyme_sd_jwt::SdJwtIssuerType::DigitalCredentialSdJwt,
            },
        },
        &mut salt_source,
    )
    .expect("receipt fixture issuance")
}

fn receipt_policy<'a>(holder: &'a TestKey, now_unix: u64) -> SdJwtReceiptVerificationPolicy<'a> {
    SdJwtReceiptVerificationPolicy::new(
        RECEIPT_ISSUER,
        RECEIPT_VCT,
        &holder.jwk,
        &holder.public,
        now_unix,
        600,
    )
}

fn credential_policy<'a>(
    holder: &'a TestKey,
    now_unix: u64,
) -> SdJwtCredentialVerificationPolicy<'a> {
    SdJwtCredentialVerificationPolicy::new(
        RECEIPT_ISSUER,
        RECEIPT_VCT,
        &holder.jwk,
        &holder.public,
        now_unix,
    )
}

#[test]
fn receipt_policy_enforces_the_shared_expected_claim_bound() {
    let issuer = gen_ed25519();
    let holder = gen_ed25519();
    let issued = issue_receipt_credential(
        &issuer,
        serde_json::to_value(&holder.jwk).expect("holder JWK JSON"),
        json!(RECEIPT_NOW),
        None,
        None,
    );
    let exact = "i".repeat(reallyme_sd_jwt::MAX_SD_JWT_EXPECTED_CLAIM_BYTES);
    let oversized = format!("{exact}i");
    let mut exact_policy = receipt_policy(&holder, RECEIPT_NOW);
    exact_policy.expected_issuer = &exact;
    let mut oversized_policy = receipt_policy(&holder, RECEIPT_NOW);
    oversized_policy.expected_issuer = &oversized;

    assert_ne!(
        verify_sd_jwt_receipt(&issued.compact, &issuer.jwk, &issuer.public, &exact_policy).err(),
        Some(SdJwtEnvelopeError::InvalidReceiptPolicy)
    );
    assert_eq!(
        verify_sd_jwt_receipt(
            &issued.compact,
            &issuer.jwk,
            &issuer.public,
            &oversized_policy,
        )
        .err(),
        Some(SdJwtEnvelopeError::InvalidReceiptPolicy)
    );
}

#[test]
fn receipt_verifier_authenticates_disclosures_claims_and_holder_binding() {
    let issuer = gen_ed25519();
    let holder = gen_ed25519();
    let issued = issue_receipt_credential(
        &issuer,
        serde_json::to_value(&holder.jwk).expect("holder JWK JSON"),
        json!(RECEIPT_NOW - 10),
        Some(json!(RECEIPT_NOW - 10)),
        Some(json!(RECEIPT_NOW + 600)),
    );

    let receipt = verify_sd_jwt_receipt(
        &issued.compact,
        &issuer.jwk,
        &issuer.public,
        &receipt_policy(&holder, RECEIPT_NOW),
    )
    .expect("valid receipt");

    assert_eq!(
        receipt
            .resolved_payload()
            .get("given_name")
            .and_then(Value::as_str),
        Some("ALICE")
    );
    assert_eq!(receipt.holder_binding().public_key(), holder.public);
    assert_eq!(receipt.disclosures().len(), 1);
}

#[test]
fn stored_credential_verifier_accepts_old_but_unexpired_credentials() {
    let issuer = gen_ed25519();
    let holder = gen_ed25519();
    let issued = issue_receipt_credential(
        &issuer,
        serde_json::to_value(&holder.jwk).expect("holder JWK JSON"),
        json!(RECEIPT_NOW - 172_800),
        Some(json!(RECEIPT_NOW - 172_800)),
        Some(json!(RECEIPT_NOW + 600)),
    );

    assert_eq!(
        verify_sd_jwt_receipt(
            &issued.compact,
            &issuer.jwk,
            &issuer.public,
            &receipt_policy(&holder, RECEIPT_NOW),
        )
        .err(),
        Some(SdJwtEnvelopeError::InvalidReceiptTemporalClaim)
    );
    let verified = verify_sd_jwt_credential(
        &issued.compact,
        &issuer.jwk,
        &issuer.public,
        &credential_policy(&holder, RECEIPT_NOW),
    )
    .expect("old unexpired credential remains presentable");
    assert_eq!(
        verified
            .resolved_payload()
            .get("given_name")
            .and_then(Value::as_str),
        Some("ALICE")
    );
}

#[test]
fn stored_credential_verifier_accepts_missing_iat_but_receipt_verifier_does_not() {
    let issuer = gen_ed25519();
    let holder = gen_ed25519();
    let issued = issue_credential_with_registered_claims(
        &issuer,
        Some(RECEIPT_ISSUER),
        serde_json::to_value(&holder.jwk).expect("holder JWK JSON"),
        None,
        Some(json!(RECEIPT_NOW - 60)),
        Some(json!(RECEIPT_NOW + 600)),
    );

    assert_eq!(
        verify_sd_jwt_receipt(
            &issued.compact,
            &issuer.jwk,
            &issuer.public,
            &receipt_policy(&holder, RECEIPT_NOW),
        )
        .err(),
        Some(SdJwtEnvelopeError::InvalidReceiptTemporalClaim)
    );
    verify_sd_jwt_credential(
        &issued.compact,
        &issuer.jwk,
        &issuer.public,
        &credential_policy(&holder, RECEIPT_NOW),
    )
    .expect("stored credential accepts optional iat");
}

#[test]
fn stored_credential_verifier_validates_selectively_disclosed_iat() {
    let issuer = gen_ed25519();
    let holder = gen_ed25519();
    let holder_jwk = serde_json::to_value(&holder.jwk).expect("holder JWK JSON");
    let valid = issue_credential_with_disclosure_policy(
        &issuer,
        Some(RECEIPT_ISSUER),
        holder_jwk.clone(),
        Some(json!(RECEIPT_NOW - 60)),
        None,
        Some(json!(RECEIPT_NOW + 600)),
        true,
    );
    let future = issue_credential_with_disclosure_policy(
        &issuer,
        Some(RECEIPT_ISSUER),
        holder_jwk,
        Some(json!(RECEIPT_NOW + 61)),
        None,
        Some(json!(RECEIPT_NOW + 600)),
        true,
    );

    verify_sd_jwt_credential(
        &valid.compact,
        &issuer.jwk,
        &issuer.public,
        &credential_policy(&holder, RECEIPT_NOW),
    )
    .expect("valid selectively disclosed iat");
    assert_eq!(
        verify_sd_jwt_credential(
            &future.compact,
            &issuer.jwk,
            &issuer.public,
            &credential_policy(&holder, RECEIPT_NOW),
        )
        .err(),
        Some(SdJwtEnvelopeError::InvalidReceiptTemporalClaim)
    );
}

#[test]
fn stored_credential_verifier_rejects_future_and_expired_credentials() {
    let issuer = gen_ed25519();
    let holder = gen_ed25519();
    let holder_jwk = serde_json::to_value(&holder.jwk).expect("holder JWK JSON");
    let future = issue_receipt_credential(
        &issuer,
        holder_jwk.clone(),
        json!(RECEIPT_NOW + 61),
        Some(json!(RECEIPT_NOW + 61)),
        Some(json!(RECEIPT_NOW + 600)),
    );
    let expired = issue_receipt_credential(
        &issuer,
        holder_jwk,
        json!(RECEIPT_NOW - 172_800),
        None,
        Some(json!(RECEIPT_NOW - 61)),
    );

    assert_eq!(
        verify_sd_jwt_credential(
            &future.compact,
            &issuer.jwk,
            &issuer.public,
            &credential_policy(&holder, RECEIPT_NOW),
        )
        .err(),
        Some(SdJwtEnvelopeError::InvalidReceiptTemporalClaim)
    );
    assert_eq!(
        verify_sd_jwt_credential(
            &expired.compact,
            &issuer.jwk,
            &issuer.public,
            &credential_policy(&holder, RECEIPT_NOW),
        )
        .err(),
        Some(SdJwtEnvelopeError::ReceiptExpired)
    );
}

#[test]
fn receipt_verifier_rejects_future_nbf_with_current_iat() {
    let issuer = gen_ed25519();
    let holder = gen_ed25519();
    let issued = issue_receipt_credential(
        &issuer,
        serde_json::to_value(&holder.jwk).expect("holder JWK JSON"),
        json!(RECEIPT_NOW),
        Some(json!(RECEIPT_NOW + 61)),
        Some(json!(RECEIPT_NOW + 600)),
    );

    assert_eq!(
        verify_sd_jwt_receipt(
            &issued.compact,
            &issuer.jwk,
            &issuer.public,
            &receipt_policy(&holder, RECEIPT_NOW),
        )
        .err(),
        Some(SdJwtEnvelopeError::CredentialNotYetValid)
    );
}

#[test]
fn invalid_x5c_policy_is_rejected_before_resolver_work() {
    let issuer = gen_p256();
    let holder = gen_ed25519();
    let issued = issue_receipt_credential(
        &issuer,
        serde_json::to_value(&holder.jwk).expect("holder JWK JSON"),
        json!(RECEIPT_NOW),
        None,
        Some(json!(RECEIPT_NOW + 600)),
    );
    let mut invalid_policy = receipt_policy(&holder, 0);
    invalid_policy.now_unix = 0;
    let mut resolver_called = false;

    let result = verify_sd_jwt_receipt_with_x5c(&issued.compact, &invalid_policy, |_| {
        resolver_called = true;
        Some(Vec::new())
    });
    assert!(!resolver_called);
    assert_eq!(result.err(), Some(SdJwtEnvelopeError::InvalidReceiptPolicy));
}

#[test]
fn receipt_verifier_authenticates_the_exact_x5c_header_chain() {
    let issuer = gen_p256();
    let holder = gen_ed25519();
    let issued = issue_receipt_credential(
        &issuer,
        serde_json::to_value(&holder.jwk).expect("holder JWK JSON"),
        json!(RECEIPT_NOW),
        None,
        Some(json!(RECEIPT_NOW + 600)),
    );
    let (issuer_jwt, suffix) = issued.compact.split_once('~').expect("SD-JWT separator");
    let mut components = issuer_jwt.split('.');
    let _old_header = components.next().expect("header");
    let payload = components.next().expect("payload");
    let _old_signature = components.next().expect("signature");
    assert!(components.next().is_none());
    let header = bytes_to_base64url(br#"{"alg":"ES256","typ":"dc+sd-jwt","x5c":["AQ=="]}"#);
    let signing_input = format!("{header}.{payload}");
    let signature_der = sign(Algorithm::P256, &issuer.private, signing_input.as_bytes())
        .expect("sign x5c credential");
    let signature =
        p256_ecdsa_der_to_jose_signature(&signature_der).expect("convert x5c signature");
    let compact = format!(
        "{signing_input}.{}~{suffix}",
        bytes_to_base64url(&signature)
    );
    let x509_subject_public_key =
        decompress_public_key(&issuer.public).expect("uncompressed X.509 subject key");
    assert_eq!(x509_subject_public_key.len(), 65);

    let receipt =
        verify_sd_jwt_receipt_with_x5c(&compact, &receipt_policy(&holder, RECEIPT_NOW), |chain| {
            assert_eq!(chain, &[vec![1_u8]]);
            Some(x509_subject_public_key.clone())
        })
        .expect("valid x5c receipt");
    assert_eq!(receipt.holder_binding().public_key(), holder.public);

    let credential = verify_sd_jwt_credential_with_x5c(
        &compact,
        &credential_policy(&holder, RECEIPT_NOW),
        |chain| {
            assert_eq!(chain, &[vec![1_u8]]);
            Some(x509_subject_public_key.clone())
        },
    )
    .expect("valid stored x5c credential");
    assert_eq!(credential.holder_binding().public_key(), holder.public);
}

#[test]
fn x5c_credential_allows_missing_issuer_only_by_explicit_policy() {
    let issuer = gen_p256();
    let holder = gen_ed25519();
    let x509_subject_public_key =
        decompress_public_key(&issuer.public).expect("uncompressed X.509 subject key");

    for issuer_claim in [None, Some("https://other.example")] {
        let issued = issue_credential_with_registered_claims(
            &issuer,
            issuer_claim,
            serde_json::to_value(&holder.jwk).expect("holder JWK JSON"),
            None,
            None,
            Some(json!(RECEIPT_NOW + 600)),
        );
        let (issuer_jwt, suffix) = issued.compact.split_once('~').expect("SD-JWT separator");
        let mut components = issuer_jwt.split('.');
        let _old_header = components.next().expect("header");
        let payload = components.next().expect("payload");
        let _old_signature = components.next().expect("signature");
        assert!(components.next().is_none());
        let header = bytes_to_base64url(
            br#"{"alg":"ES256","typ":"dc+sd-jwt","kid":"test-p256-key","x5c":["AQ=="]}"#,
        );
        let signing_input = format!("{header}.{payload}");
        let signature_der = sign(Algorithm::P256, &issuer.private, signing_input.as_bytes())
            .expect("sign x5c credential");
        let signature =
            p256_ecdsa_der_to_jose_signature(&signature_der).expect("convert x5c signature");
        let compact = format!(
            "{signing_input}.{}~{suffix}",
            bytes_to_base64url(&signature)
        );

        if issuer_claim.is_none() {
            assert_eq!(
                verify_sd_jwt_credential_with_x5c(
                    &compact,
                    &credential_policy(&holder, RECEIPT_NOW),
                    |_| Some(x509_subject_public_key.clone()),
                )
                .err(),
                Some(SdJwtEnvelopeError::ReceiptClaimMismatch)
            );
            let mut policy = credential_policy(&holder, RECEIPT_NOW);
            policy.x5c_allow_missing_issuer_claim = true;
            policy.issuer_allow_embedded_key_header = true;
            assert_eq!(
                verify_sd_jwt_credential(
                    &compact,
                    &issuer.jwk,
                    &issuer.public,
                    &policy,
                )
                .err(),
                Some(SdJwtEnvelopeError::ReceiptClaimMismatch)
            );
            let credential = verify_sd_jwt_credential_with_x5c(
                &compact,
                &policy,
                |_| Some(x509_subject_public_key.clone()),
            )
            .expect("authenticated x5c conveys the issuer when policy permits it");
            assert_eq!(credential.holder_binding().public_key(), holder.public);
        } else {
            let mut policy = credential_policy(&holder, RECEIPT_NOW);
            policy.x5c_allow_missing_issuer_claim = true;
            assert_eq!(
                verify_sd_jwt_credential_with_x5c(&compact, &policy, |_| {
                    Some(x509_subject_public_key.clone())
                })
                .err(),
                Some(SdJwtEnvelopeError::ReceiptClaimMismatch)
            );
        }
    }
}

#[test]
fn generic_verifier_requires_explicit_x5c_policy_and_keeps_caller_key_authoritative() {
    let issuer = gen_p256();
    let other_issuer = gen_p256();
    let header = bytes_to_base64url(
        br#"{"alg":"ES256","typ":"dc+sd-jwt","kid":"test-p256-key","x5c":["AQ=="]}"#,
    );
    let payload =
        bytes_to_base64url(br#"{"iss":"https://issuer.example","vct":"urn:example:credential"}"#);
    let signing_input = format!("{header}.{payload}");
    let signature_der = sign(Algorithm::P256, &issuer.private, signing_input.as_bytes())
        .expect("sign embedded-header credential");
    let signature = p256_ecdsa_der_to_jose_signature(&signature_der)
        .expect("convert embedded-header signature");
    let compact = format!("{signing_input}.{}~", bytes_to_base64url(&signature));

    assert!(verify_sd_jwt(
        &compact,
        &issuer.jwk,
        &issuer.public,
        &SdJwtVerificationOptions::new(VERIFY_NOW_UNIX),
    )
    .is_err());

    let permitted = SdJwtVerificationOptions {
        issuer_allow_embedded_key_header: true,
        ..SdJwtVerificationOptions::new(VERIFY_NOW_UNIX)
    };
    let issuer_public = &issuer.public;
    let other_issuer_public = &other_issuer.public;
    reallyme_jose::jwt::decode_verify_jwt_claims_json_signature_only_with_header_validation(
        compact.trim_end_matches('~'),
        &issuer.jwk,
        issuer_public,
        &reallyme_jose::jwt::JwtHeaderValidationOptions::new(
            true,
            true,
            &["dc+sd-jwt", "vc+sd-jwt", "example+sd-jwt", "JWT"],
        ),
    )
    .expect("low-level embedded-header JWT validates");
    verify_sd_jwt(&compact, &issuer.jwk, issuer_public, &permitted)
        .expect("explicit embedded-header policy accepts configured issuer signature");
    assert!(verify_sd_jwt(&compact, &other_issuer.jwk, other_issuer_public, &permitted,).is_err());
}

#[test]
fn receipt_verifier_rejects_malformed_or_untrusted_x5c_headers() {
    let holder = gen_ed25519();
    let policy = receipt_policy(&holder, RECEIPT_NOW);
    let duplicate =
        bytes_to_base64url(br#"{"alg":"ES256","typ":"dc+sd-jwt","x5c":["AQ=="],"x5c":["Ag=="]}"#);
    let malformed = format!("{duplicate}.e30.signature~");
    assert_eq!(
        verify_sd_jwt_receipt_with_x5c(&malformed, &policy, |_| Some(vec![4_u8; 65])).err(),
        Some(SdJwtEnvelopeError::InvalidIssuerJwt)
    );

    let header = bytes_to_base64url(br#"{"alg":"ES256","typ":"dc+sd-jwt","x5c":["AQ=="]}"#);
    let untrusted = format!("{header}.e30.signature~");
    assert_eq!(
        verify_sd_jwt_receipt_with_x5c(&untrusted, &policy, |_| None).err(),
        Some(SdJwtEnvelopeError::InvalidIssuerJwt)
    );
}

#[test]
fn receipt_verifier_rejects_wrong_or_private_holder_key_and_appended_kb_jwt() {
    let issuer = gen_ed25519();
    let holder = gen_ed25519();
    let other_holder = gen_ed25519();
    let issued = issue_receipt_credential(
        &issuer,
        serde_json::to_value(&holder.jwk).expect("holder JWK JSON"),
        json!(RECEIPT_NOW),
        None,
        None,
    );
    assert_eq!(
        verify_sd_jwt_receipt(
            &issued.compact,
            &issuer.jwk,
            &issuer.public,
            &receipt_policy(&other_holder, RECEIPT_NOW),
        )
        .err(),
        Some(SdJwtEnvelopeError::ReceiptHolderBindingMismatch)
    );

    let mut private_jwk = serde_json::to_value(&holder.jwk)
        .expect("holder JWK JSON")
        .as_object()
        .expect("holder JWK object")
        .clone();
    private_jwk.insert("d".to_owned(), Value::String("secret".to_owned()));
    let private = issue_receipt_credential(
        &issuer,
        Value::Object(private_jwk),
        json!(RECEIPT_NOW),
        None,
        None,
    );
    assert_eq!(
        verify_sd_jwt_receipt(
            &private.compact,
            &issuer.jwk,
            &issuer.public,
            &receipt_policy(&holder, RECEIPT_NOW),
        )
        .err(),
        Some(SdJwtEnvelopeError::InvalidReceiptHolderBinding)
    );

    let with_kb = format!("{}invalid.invalid.invalid", issued.compact);
    assert_eq!(
        verify_sd_jwt_receipt(
            &with_kb,
            &issuer.jwk,
            &issuer.public,
            &receipt_policy(&holder, RECEIPT_NOW),
        )
        .err(),
        Some(SdJwtEnvelopeError::UnexpectedReceiptKeyBindingJwt)
    );
}

#[test]
fn receipt_verifier_rejects_stale_future_expired_and_malformed_time_claims() {
    let issuer = gen_ed25519();
    let holder = gen_ed25519();
    let holder_jwk = serde_json::to_value(&holder.jwk).expect("holder JWK JSON");
    let cases = [
        (
            issue_receipt_credential(
                &issuer,
                holder_jwk.clone(),
                json!(RECEIPT_NOW - 1_000),
                None,
                None,
            ),
            SdJwtEnvelopeError::InvalidReceiptTemporalClaim,
        ),
        (
            issue_receipt_credential(
                &issuer,
                holder_jwk.clone(),
                json!(RECEIPT_NOW + 61),
                None,
                None,
            ),
            SdJwtEnvelopeError::InvalidReceiptTemporalClaim,
        ),
        (
            issue_receipt_credential(
                &issuer,
                holder_jwk.clone(),
                json!(RECEIPT_NOW - 120),
                None,
                Some(json!(RECEIPT_NOW - 61)),
            ),
            SdJwtEnvelopeError::ReceiptExpired,
        ),
        (
            issue_receipt_credential(
                &issuer,
                holder_jwk,
                Value::String("not-a-numeric-date".to_owned()),
                None,
                None,
            ),
            SdJwtEnvelopeError::InvalidReceiptTemporalClaim,
        ),
    ];
    for (issued, expected) in cases {
        assert_eq!(
            verify_sd_jwt_receipt(
                &issued.compact,
                &issuer.jwk,
                &issuer.public,
                &receipt_policy(&holder, RECEIPT_NOW),
            )
            .err(),
            Some(expected)
        );
    }
}

#[test]
fn receipt_verifier_rejects_tampered_disclosure_hash() {
    let issuer = gen_ed25519();
    let holder = gen_ed25519();
    let issued = issue_receipt_credential(
        &issuer,
        serde_json::to_value(&holder.jwk).expect("holder JWK JSON"),
        json!(RECEIPT_NOW),
        None,
        None,
    );
    let tampered = serialize_sd_jwt_compact(
        &issued.issuer_signed_jwt,
        &[bytes_to_base64url(
            br#"["MDEyMzQ1Njc4OWFiY2RlZg","given_name","MALLORY"]"#,
        )],
    )
    .expect("tampered compact");
    assert_eq!(
        verify_sd_jwt_receipt(
            &tampered,
            &issuer.jwk,
            &issuer.public,
            &receipt_policy(&holder, RECEIPT_NOW),
        )
        .err(),
        Some(SdJwtEnvelopeError::UnmatchedDisclosure)
    );
}
