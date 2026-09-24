// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

const RECEIPT_NOW: u64 = 1_800_000_000;
const RECEIPT_ISSUER: &str = "https://issuer.example";
const RECEIPT_VCT: &str = "urn:example:credential";

fn issue_receipt_credential(
    issuer: &TestKey,
    holder_jwk: Value,
    issued_at: Value,
    not_before: Option<Value>,
    expires_at: Option<Value>,
) -> reallyme_sd_jwt::IssuedSdJwt {
    let mut claims = Map::new();
    claims.insert("iss".to_owned(), Value::String(RECEIPT_ISSUER.to_owned()));
    claims.insert("vct".to_owned(), Value::String(RECEIPT_VCT.to_owned()));
    claims.insert("iat".to_owned(), issued_at);
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

fn receipt_policy<'a>(
    holder: &'a TestKey,
    now_unix: u64,
) -> SdJwtReceiptVerificationPolicy<'a> {
    SdJwtReceiptVerificationPolicy::new(
        RECEIPT_ISSUER,
        RECEIPT_VCT,
        &holder.jwk,
        &holder.public,
        now_unix,
        600,
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
    let signature = p256_ecdsa_der_to_jose_signature(&signature_der)
        .expect("convert x5c signature");
    let compact = format!("{signing_input}.{}~{suffix}", bytes_to_base64url(&signature));
    let x509_subject_public_key =
        decompress_public_key(&issuer.public).expect("uncompressed X.509 subject key");
    assert_eq!(x509_subject_public_key.len(), 65);

    let receipt = verify_sd_jwt_receipt_with_x5c(
        &compact,
        &receipt_policy(&holder, RECEIPT_NOW),
        |chain| {
            assert_eq!(chain, &[vec![1_u8]]);
            Some(x509_subject_public_key.clone())
        },
    )
    .expect("valid x5c receipt");
    assert_eq!(receipt.holder_binding().public_key(), holder.public);
}

#[test]
fn generic_verifier_requires_explicit_x5c_policy_and_keeps_caller_key_authoritative() {
    let issuer = gen_p256();
    let other_issuer = gen_p256();
    let header = bytes_to_base64url(
        br#"{"alg":"ES256","typ":"dc+sd-jwt","kid":"test-p256-key","x5c":["AQ=="]}"#,
    );
    let payload = bytes_to_base64url(
        br#"{"iss":"https://issuer.example","vct":"urn:example:credential"}"#,
    );
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
        &SdJwtVerificationOptions::default(),
    )
    .is_err());

    let permitted = SdJwtVerificationOptions {
        issuer_allow_embedded_key_header: true,
        ..SdJwtVerificationOptions::default()
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
    assert!(verify_sd_jwt(
        &compact,
        &other_issuer.jwk,
        other_issuer_public,
        &permitted,
    )
    .is_err());
}

#[test]
fn receipt_verifier_rejects_malformed_or_untrusted_x5c_headers() {
    let holder = gen_ed25519();
    let policy = receipt_policy(&holder, RECEIPT_NOW);
    let duplicate = bytes_to_base64url(
        br#"{"alg":"ES256","typ":"dc+sd-jwt","x5c":["AQ=="],"x5c":["Ag=="]}"#,
    );
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
