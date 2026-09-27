// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#[test]
fn top_level_strategy_discloses_dotted_and_uri_claim_names() {
    let issuer = gen_ed25519();
    let claims = json!({
        "iss": "https://example.com/issuer",
        "vct": "urn:example:test",
        "email.verified": true,
        "https://example.com/claims/ssn": "123-45-6789",
    });
    let mut salts = DeterministicSaltSource::new();

    let issued = issue_sd_jwt(
        SdJwtIssuanceInput {
            claims: claims.clone(),
            issuer_jwk: &issuer.jwk,
            issuer_private_key: &issuer.private,
            policy: SdJwtIssuancePolicy::default(),
        },
        &mut salts,
    )
    .expect("valid SD-JWT issuance must succeed");

    assert!(issued.issuer_payload.get("email.verified").is_none());
    assert!(issued
        .issuer_payload
        .get("https://example.com/claims/ssn")
        .is_none());
    let verified = verify_sd_jwt(
        &issued.compact,
        &issuer.jwk,
        &issuer.public,
        &SdJwtVerificationOptions::new(VERIFY_NOW_UNIX),
    )
    .expect("issued SD-JWT must verify");
    assert_eq!(verified.resolved_payload(), &claims);
}

#[test]
fn issuance_rejects_json_path_that_matches_no_claim() {
    let issuer = gen_ed25519();
    let mut salts = DeterministicSaltSource::new();
    let error = issue_sd_jwt(
        SdJwtIssuanceInput {
            claims: json!({
                "iss": "https://example.com/issuer",
                "vct": "urn:example:test",
                "given_name": "Ada",
            }),
            issuer_jwk: &issuer.jwk,
            issuer_private_key: &issuer.private,
            policy: SdJwtIssuancePolicy {
                disclosure_strategy: SdJwtDisclosureStrategy::JsonPaths(BTreeSet::from([
                    "$.family_name".to_owned(),
                ])),
                ..SdJwtIssuancePolicy::default()
            },
        },
        &mut salts,
    )
    .expect_err("an unmatched disclosure path must fail issuance");

    assert_eq!(error, SdJwtEnvelopeError::DisclosurePathNotFound);
}

#[test]
fn sd_jwt_vc_typ_variants_require_vct() {
    let issuer = gen_ed25519();
    for media_type in ["DC+SD-JWT", "application/dc+sd-jwt"] {
        let issuer_signed_jwt = encode_signed_jwt_with_header_options(
            &json!({"iss": "https://example.com/issuer"}),
            &issuer.jwk,
            &issuer.private,
            &JwtHeaderEncodeOptions::new(Some(media_type.to_owned())),
        )
        .expect("issuer JWT");
        let compact = serialize_sd_jwt_compact(&issuer_signed_jwt, &[])
            .expect("compact SD-JWT");

        assert_eq!(
            verify_sd_jwt(
                &compact,
                &issuer.jwk,
                &issuer.public,
                &SdJwtVerificationOptions::new(VERIFY_NOW_UNIX),
            ),
            Err(SdJwtEnvelopeError::InvalidIssuerJwt),
            "{media_type} must enforce vct",
        );
    }
}
