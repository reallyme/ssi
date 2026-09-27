// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

fn bound_dpop_proof() -> Result<(DpopProof, DpopValidationContext), OauthError> {
    let public_jwk = json!({"kty":"EC","crv":"P-256","x":"x","y":"y"});
    let proof = DpopProofRequest {
        method: "POST".to_owned(),
        target_uri: "https://as.example/token".to_owned(),
        jti: "request-binding".to_owned(),
        iat: 1_700_000_000,
        public_jwk: public_jwk.clone(),
        access_token: Some("access-token".to_owned()),
        nonce: Some("nonce".to_owned()),
    }
    .sign(&TestSigner)?;
    let context = DpopValidationContext {
        method: "POST".to_owned(),
        target_uri: "https://as.example/token".to_owned(),
        access_token: Some("access-token".to_owned()),
        nonce: Some("nonce".to_owned()),
        earliest_iat: 1_699_999_990,
        latest_iat: 1_700_000_010,
        confirmed_jkt: Some(jwk_thumbprint(&public_jwk)?),
    };
    Ok((proof, context))
}

#[test]
fn dpop_validation_enforces_inclusive_issued_at_boundaries() -> Result<(), OauthError> {
    const EARLIEST_IAT: i64 = 1_699_999_990;
    const LATEST_IAT: i64 = 1_700_000_010;

    for (iat, expected_valid) in [
        (EARLIEST_IAT - 1, false),
        (EARLIEST_IAT, true),
        (LATEST_IAT, true),
        (LATEST_IAT + 1, false),
    ] {
        let proof = DpopProofRequest {
            method: "POST".to_owned(),
            target_uri: "https://as.example/token".to_owned(),
            jti: format!("iat-boundary-{iat}"),
            iat,
            public_jwk: json!({"kty":"EC","crv":"P-256","x":"x","y":"y"}),
            access_token: None,
            nonce: None,
        }
        .sign(&TestSigner)?;
        let result = proof.validate(
            &DpopValidationContext {
                method: "POST".to_owned(),
                target_uri: "https://as.example/token".to_owned(),
                access_token: None,
                nonce: None,
                earliest_iat: EARLIEST_IAT,
                latest_iat: LATEST_IAT,
                confirmed_jkt: None,
            },
            &TestVerifier::new(),
        );

        assert_eq!(result.is_ok(), expected_valid, "unexpected result for iat={iat}");
    }

    Ok(())
}

#[test]
fn dpop_validation_rejects_mismatched_access_token_jkt_binding() -> Result<(), OauthError> {
    let proof = DpopProofRequest {
        method: "POST".to_owned(),
        target_uri: "https://as.example/token".to_owned(),
        jti: "jti-2b".to_owned(),
        iat: 1_700_000_000,
        public_jwk: json!({"kty":"EC","crv":"P-256","x":"x","y":"y"}),
        access_token: Some("access-token".to_owned()),
        nonce: None,
    }
    .sign(&TestSigner)?;

    let context = DpopValidationContext {
        method: "POST".to_owned(),
        target_uri: "https://as.example/token".to_owned(),
        access_token: Some("access-token".to_owned()),
        nonce: None,
        earliest_iat: 1_699_999_990,
        latest_iat: 1_700_000_010,
        confirmed_jkt: Some("not-the-proof-key".to_owned()),
    };

    assert_eq!(
        proof
            .validate(&context, &TestVerifier::new())
            .err()
            .map(|error| error.reason()),
        Some(Reason::InvalidDpopProof)
    );
    Ok(())
}

#[test]
fn dpop_validation_rejects_wrong_http_method() -> Result<(), OauthError> {
    let (proof, mut context) = bound_dpop_proof()?;
    context.method = "GET".to_owned();

    assert_eq!(
        proof
            .validate(&context, &TestVerifier::new())
            .err()
            .map(|error| error.reason()),
        Some(Reason::InvalidDpopProof)
    );
    Ok(())
}

#[test]
fn dpop_validation_rejects_wrong_target_uri() -> Result<(), OauthError> {
    let (proof, mut context) = bound_dpop_proof()?;
    context.target_uri = "https://as.example/other".to_owned();

    assert_eq!(
        proof
            .validate(&context, &TestVerifier::new())
            .err()
            .map(|error| error.reason()),
        Some(Reason::InvalidDpopProof)
    );
    Ok(())
}

#[test]
fn dpop_validation_rejects_wrong_nonce() -> Result<(), OauthError> {
    let (proof, mut context) = bound_dpop_proof()?;
    context.nonce = Some("different-nonce".to_owned());

    assert_eq!(
        proof
            .validate(&context, &TestVerifier::new())
            .err()
            .map(|error| error.reason()),
        Some(Reason::InvalidDpopProof)
    );
    Ok(())
}

#[test]
fn dpop_validation_rejects_wrong_or_missing_access_token_hash() -> Result<(), OauthError> {
    let (proof, mut context) = bound_dpop_proof()?;
    context.access_token = Some("different-access-token".to_owned());
    assert_eq!(
        proof
            .validate(&context, &TestVerifier::new())
            .err()
            .map(|error| error.reason()),
        Some(Reason::InvalidDpopProof)
    );

    let public_jwk = json!({"kty":"EC","crv":"P-256","x":"x","y":"y"});
    let proof_without_hash = DpopProofRequest {
        method: "POST".to_owned(),
        target_uri: "https://as.example/token".to_owned(),
        jti: "missing-access-token-hash".to_owned(),
        iat: 1_700_000_000,
        public_jwk: public_jwk.clone(),
        access_token: None,
        nonce: Some("nonce".to_owned()),
    }
    .sign(&TestSigner)?;
    let required_hash_context = DpopValidationContext {
        method: "POST".to_owned(),
        target_uri: "https://as.example/token".to_owned(),
        access_token: Some("access-token".to_owned()),
        nonce: Some("nonce".to_owned()),
        earliest_iat: 1_699_999_990,
        latest_iat: 1_700_000_010,
        confirmed_jkt: Some(jwk_thumbprint(&public_jwk)?),
    };
    assert_eq!(
        proof_without_hash
            .validate(&required_hash_context, &TestVerifier::new())
            .err()
            .map(|error| error.reason()),
        Some(Reason::InvalidDpopProof)
    );
    Ok(())
}

#[test]
fn jwk_thumbprint_ignores_member_order_and_extra_fields() -> Result<(), OauthError> {
    let first = json!({
        "kty": "EC",
        "crv": "P-256",
        "x": "x-coordinate",
        "y": "y-coordinate",
        "kid": "ignored-key-id"
    });
    let second = json!({
        "kid": "different-ignored-key-id",
        "y": "y-coordinate",
        "x": "x-coordinate",
        "crv": "P-256",
        "kty": "EC"
    });

    assert_eq!(jwk_thumbprint(&first)?, jwk_thumbprint(&second)?);
    Ok(())
}
