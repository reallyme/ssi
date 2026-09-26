// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#[test]
fn attestation_client_authentication_rejects_missing_or_non_public_cnf_jwk(
) -> Result<(), OauthError> {
    let invalid_keys = [
        Value::Null,
        json!({"kty": "EC", "crv": "P-256", "x": "x"}),
        json!({"kty": "oct", "k": "secret"}),
        json!({"kty": "EC", "crv": "P-256", "x": "x", "y": "y", "d": "private"}),
        json!({"kty": "EC", "use": "enc", "crv": "P-256", "x": "x", "y": "y"}),
        json!({"kty": "EC", "alg": "HS256", "crv": "P-256", "x": "x", "y": "y"}),
        json!({"kty": "EC", "key_ops": ["sign"], "crv": "P-256", "x": "x", "y": "y"}),
        json!({"kty": "EC", "crv": "P-256", "x": "x", "y": "y", "x5u": "https://keys.example/cert.pem"}),
        json!({"kty": "EC", "crv": "P-256", "x": "x", "y": "y", "x5c": ["certificate"]}),
    ];
    let pop = AttestationPopRequest {
        audience: "https://as.example".to_owned(),
        jti: "pop-invalid-cnf".to_owned(),
        iat: 1_700_000_000,
        challenge: Some("challenge".to_owned()),
    }
    .sign(&TestSigner)?;

    for invalid_key in invalid_keys {
        let attestation = client_attestation(invalid_key)?;
        let auth = AttestationClientAuthentication::new(
            attestation.as_str().to_owned(),
            pop.as_str().to_owned(),
        )?;
        let verifier = TestVerifier::new();
        let result = validate_attestation_client_authentication(
            &auth,
            &AttestationClientAuthenticationValidationContext {
                expected_audience: "https://as.example".to_owned(),
                expected_challenge: Some("challenge".to_owned()),
                earliest_iat: 1_699_999_990,
                latest_iat: 1_700_000_010,
                current_time: 1_700_000_000,
                max_trust_evidence_age_seconds: 30,
            },
            &verifier,
        );

        assert_eq!(
            result.err().map(|error| error.reason()),
            Some(Reason::InvalidClientAttestation)
        );
        assert!(!verifier.pop_signature_checked.get());
        assert!(!verifier.replay_checked.get());
    }

    let attestation_without_confirmation = client_attestation_with_claims(json!({
        "sub": "wallet-client",
        "iat": 1_699_999_000_i64,
        "exp": 1_700_001_000_i64,
    }))?;
    let auth = AttestationClientAuthentication::new(
        attestation_without_confirmation.as_str().to_owned(),
        pop.as_str().to_owned(),
    )?;
    let verifier = TestVerifier::new();
    let result = validate_attestation_client_authentication(
        &auth,
        &AttestationClientAuthenticationValidationContext {
            expected_audience: "https://as.example".to_owned(),
            expected_challenge: Some("challenge".to_owned()),
            earliest_iat: 1_699_999_990,
            latest_iat: 1_700_000_010,
            current_time: 1_700_000_000,
            max_trust_evidence_age_seconds: 30,
        },
        &verifier,
    );
    assert_eq!(
        result.err().map(|error| error.reason()),
        Some(Reason::InvalidClientAttestation)
    );
    assert!(!verifier.pop_signature_checked.get());
    assert!(!verifier.replay_checked.get());
    Ok(())
}

#[test]
fn attestation_client_authentication_rejects_ambiguous_confirmation_claim() -> Result<(), OauthError>
{
    let public_jwk = test_client_instance_jwk("ambiguous-confirmation-key");
    let attestation = client_attestation_with_claims(json!({
        "sub": "wallet-client",
        "iat": 1_699_999_000_i64,
        "exp": 1_700_001_000_i64,
        "cnf": {
            "jwk": public_jwk,
            "jkt": "a-second-key-binding"
        }
    }))?;
    let pop = AttestationPopRequest {
        audience: "https://as.example".to_owned(),
        jti: "pop-ambiguous-confirmation".to_owned(),
        iat: 1_700_000_000,
        challenge: Some("challenge".to_owned()),
    }
    .sign(&TestSigner)?;
    let authentication = AttestationClientAuthentication::new(
        attestation.as_str().to_owned(),
        pop.as_str().to_owned(),
    )?;
    let verifier = TestVerifier::new();
    let result = validate_attestation_client_authentication(
        &authentication,
        &AttestationClientAuthenticationValidationContext {
            expected_audience: "https://as.example".to_owned(),
            expected_challenge: Some("challenge".to_owned()),
            earliest_iat: 1_699_999_990,
            latest_iat: 1_700_000_010,
            current_time: 1_700_000_000,
            max_trust_evidence_age_seconds: 30,
        },
        &verifier,
    );

    assert_eq!(
        result.err().map(|error| error.reason()),
        Some(Reason::InvalidClientAttestation)
    );
    assert!(!verifier.pop_signature_checked.get());
    assert!(!verifier.replay_checked.get());
    Ok(())
}

#[test]
fn attestation_client_authentication_rejects_pop_algorithm_key_family_mismatch(
) -> Result<(), OauthError> {
    let pop = AttestationPopRequest {
        audience: "https://as.example".to_owned(),
        jti: "pop-key-family-mismatch".to_owned(),
        iat: 1_700_000_000,
        challenge: Some("challenge".to_owned()),
    }
    .sign(&TestSigner)?;
    let attestation = client_attestation(json!({
        "kty": "RSA",
        "n": "public-modulus",
        "e": "AQAB"
    }))?;
    let authentication = AttestationClientAuthentication::new(
        attestation.as_str().to_owned(),
        pop.as_str().to_owned(),
    )?;
    let verifier = TestVerifier::new();
    let result = validate_attestation_client_authentication(
        &authentication,
        &AttestationClientAuthenticationValidationContext {
            expected_audience: "https://as.example".to_owned(),
            expected_challenge: Some("challenge".to_owned()),
            earliest_iat: 1_699_999_990,
            latest_iat: 1_700_000_010,
            current_time: 1_700_000_000,
            max_trust_evidence_age_seconds: 30,
        },
        &verifier,
    );

    assert_eq!(
        result.err().map(|error| error.reason()),
        Some(Reason::AttestationKeyBindingFailed)
    );
    assert!(!verifier.pop_signature_checked.get());
    assert!(!verifier.replay_checked.get());
    Ok(())
}

#[test]
fn attestation_client_authentication_rejects_wrong_challenge() -> Result<(), OauthError> {
    let public_jwk = test_client_instance_jwk("challenge-test-x");
    let pop = AttestationPopRequest {
        audience: "https://as.example".to_owned(),
        jti: "pop-2".to_owned(),
        iat: 1_700_000_000,
        challenge: Some("challenge".to_owned()),
    }
    .sign(&TestSigner)?;
    let attestation = client_attestation(public_jwk)?;
    let auth = AttestationClientAuthentication::new(
        attestation.as_str().to_owned(),
        pop.as_str().to_owned(),
    )?;

    let err = match validate_attestation_client_authentication(
        &auth,
        &AttestationClientAuthenticationValidationContext {
            expected_audience: "https://as.example".to_owned(),
            expected_challenge: Some("other-challenge".to_owned()),
            earliest_iat: 1_699_999_990,
            latest_iat: 1_700_000_010,
            current_time: 1_700_000_000,
            max_trust_evidence_age_seconds: 30,
        },
        &TestVerifier::new(),
    ) {
        Ok(_) => return Err(OauthError::new(Reason::InvalidClientAttestation)),
        Err(err) => err,
    };

    assert_eq!(err.reason(), Reason::InvalidClientAttestation);
    Ok(())
}

#[test]
fn bearer_owners_redact_and_zeroize_protocol_values() -> Result<(), OauthError> {
    fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}
    assert_zeroize_on_drop::<CompactJwt>();
    assert_zeroize_on_drop::<AttestationClientAuthentication>();
    assert_zeroize_on_drop::<AttestedClientKey>();
    assert_zeroize_on_drop::<VerifiedAttestationClientAuthentication>();
    assert_zeroize_on_drop::<DpopProofRequest>();
    assert_zeroize_on_drop::<ParRequest>();

    let mut jwt = CompactJwt::new("header.private-claims.signature".to_owned())?;
    assert!(!format!("{jwt:?}").contains("private-claims"));
    jwt.zeroize();
    assert!(jwt.as_str().is_empty());

    let mut authentication =
        AttestationClientAuthentication::new("a.b.c".to_owned(), "d.e.f".to_owned())?;
    assert!(!format!("{authentication:?}").contains("a.b.c"));
    authentication.zeroize();
    assert!(authentication.client_attestation.is_empty());
    assert!(authentication.client_attestation_pop.is_empty());
    Ok(())
}
