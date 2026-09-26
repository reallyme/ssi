// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#[test]
fn jwk_thumbprint_supports_okp_and_rsa_required_members() -> Result<(), OauthError> {
    let okp = json!({"kty":"OKP","crv":"Ed25519","x":"public-okp-key"});
    let rsa = json!({"kty":"RSA","e":"AQAB","n":"public-rsa-modulus"});

    let okp_thumbprint = jwk_thumbprint(&okp)?;
    let rsa_thumbprint = jwk_thumbprint(&rsa)?;

    assert!(!okp_thumbprint.is_empty());
    assert!(!rsa_thumbprint.is_empty());
    assert_ne!(okp_thumbprint, rsa_thumbprint);
    Ok(())
}

#[test]
fn jwk_thumbprint_vectors_match_or_fail_closed() -> Result<(), OauthError> {
    let suite: JwkThumbprintVectorSuite =
        serde_json::from_str(include_str!("../../../../vectors/jwk-thumbprint.json"))
            .map_err(|_| OauthError::new(Reason::InvalidDpopProof))?;

    assert!(!suite.cases.is_empty());

    for case in suite.cases {
        let result = jwk_thumbprint(&case.jwk);
        match (case.expected_thumbprint, case.expected_error.as_deref()) {
            (Some(expected), None) => {
                let actual = result?;
                assert_eq!(actual, expected, "{}", case.id);
            }
            (None, Some("InvalidDpopProof")) => {
                assert_eq!(
                    result.err().map(|error| error.reason()),
                    Some(Reason::InvalidDpopProof),
                    "{}",
                    case.id
                );
            }
            _ => return Err(OauthError::new(Reason::InvalidDpopProof)),
        }
    }

    Ok(())
}

#[test]
fn jwk_thumbprint_positive_vectors_match() -> Result<(), OauthError> {
    let suite: JwkThumbprintVectorSuite =
        serde_json::from_str(include_str!("../../../../vectors/jwk-thumbprint.json"))
            .map_err(|_| OauthError::new(Reason::InvalidDpopProof))?;

    let mut matched = false;
    for case in suite.cases {
        if let Some(expected) = case.expected_thumbprint {
            let actual = jwk_thumbprint(&case.jwk)?;
            assert_eq!(actual, expected, "{}", case.id);
            matched = true;
        }
    }

    assert!(matched);
    Ok(())
}

#[test]
fn jwk_thumbprint_negative_vectors_fail_closed() -> Result<(), OauthError> {
    let suite: JwkThumbprintVectorSuite =
        serde_json::from_str(include_str!("../../../../vectors/jwk-thumbprint.json"))
            .map_err(|_| OauthError::new(Reason::InvalidDpopProof))?;

    let mut matched = false;
    for case in suite.cases {
        if case.expected_error.as_deref() == Some("InvalidDpopProof") {
            assert_eq!(
                jwk_thumbprint(&case.jwk).err().map(|error| error.reason()),
                Some(Reason::InvalidDpopProof),
                "{}",
                case.id
            );
            matched = true;
        }
    }

    assert!(matched);
    Ok(())
}

#[test]
fn jwk_thumbprint_rejects_missing_required_member() {
    let result = jwk_thumbprint(&json!({"kty":"EC","crv":"P-256","x":"x-coordinate"}));

    assert_eq!(
        result.err().map(|error| error.reason()),
        Some(Reason::InvalidDpopProof)
    );
}

#[test]
fn jwk_thumbprint_rejects_oversized_required_member() {
    let result = jwk_thumbprint(&json!({
        "kty": "RSA",
        "e": "AQAB",
        "n": "n".repeat(8_193)
    }));

    assert_eq!(
        result.err().map(|error| error.reason()),
        Some(Reason::InvalidDpopProof)
    );
}

#[test]
fn dpop_header_rejects_symmetric_algorithm() {
    // RFC 9449 §4.2: only registered asymmetric algorithms are accepted.
    let result = DpopHeader::new(
        "HS256".to_owned(),
        json!({"kty":"EC","crv":"P-256","x":"x","y":"y"}),
    );
    assert_eq!(
        result.err().map(|error| error.reason()),
        Some(Reason::InvalidDpopProof)
    );
}

#[test]
fn dpop_header_rejects_symmetric_jwk() {
    // A symmetric `oct` key (with `k`) must never be accepted as a proof key.
    let result = DpopHeader::new("ES256".to_owned(), json!({"kty":"oct","k":"c2VjcmV0"}));
    assert_eq!(
        result.err().map(|error| error.reason()),
        Some(Reason::InvalidDpopProof)
    );
}

#[test]
fn dpop_header_rejects_algorithm_confusion_and_alternate_key_material() {
    let cases = [
        json!({"kty":"RSA","e":"AQAB","n":"public-modulus"}),
        json!({"kty":"EC","crv":"P-256","x":"x","y":"y","alg":"ES384"}),
        json!({"kty":"EC","crv":"P-256","x":"x","y":"y","x5c":["certificate"]}),
    ];

    for jwk in cases {
        assert_eq!(
            DpopHeader::new("ES256".to_owned(), jwk)
                .err()
                .map(|error| error.reason()),
            Some(Reason::InvalidDpopProof)
        );
    }
}

#[test]
fn metadata_accepts_par_dpop_and_s256() -> Result<(), OauthError> {
    valid_authorization_server_metadata().validate()
}

#[test]
fn metadata_round_trips_client_attestation_challenge_endpoint() -> Result<(), OauthError> {
    let metadata = valid_authorization_server_metadata();
    let encoded = metadata.to_json()?;
    let decoded = AuthorizationServerMetadata::parse_json(&encoded)?;
    assert_eq!(
        decoded.challenge_endpoint.as_deref(),
        Some("https://as.example/challenge")
    );
    Ok(())
}

#[test]
fn metadata_rejects_malformed_and_non_https_challenge_endpoints() {
    for challenge_endpoint in ["not-a-url", "http://as.example/challenge"] {
        let mut metadata = valid_authorization_server_metadata();
        metadata.challenge_endpoint = Some(challenge_endpoint.to_owned());
        assert_eq!(
            metadata.validate().err().map(|error| error.reason()),
            Some(Reason::InvalidUrl)
        );
    }
}

#[test]
fn metadata_rejects_oversized_documents_before_deserialization() {
    const OVERSIZED_PADDING_BYTES: usize = 65_536;
    let padding = "x".repeat(OVERSIZED_PADDING_BYTES);
    let document = format!(
        r#"{{"issuer":"https://as.example","challenge_endpoint":"https://as.example/challenge","padding":"{padding}"}}"#
    );
    assert_eq!(
        AuthorizationServerMetadata::parse_json(&document)
            .err()
            .map(|error| error.reason()),
        Some(Reason::InvalidJson)
    );
}

#[test]
fn metadata_round_trips_refresh_token_grant_support() -> Result<(), OauthError> {
    let mut metadata = valid_authorization_server_metadata();
    metadata.grant_types_supported =
        Some(vec![GrantType::AuthorizationCode, GrantType::RefreshToken]);

    let encoded = metadata.to_json()?;
    let decoded = AuthorizationServerMetadata::parse_json(&encoded)?;
    assert_eq!(
        decoded.grant_types_supported,
        metadata.grant_types_supported
    );
    Ok(())
}

#[test]
fn metadata_rejects_unsupported_pkce_method() {
    let mut metadata = valid_authorization_server_metadata();
    metadata.code_challenge_methods_supported = Some(vec!["plain".to_owned()]);

    assert_eq!(
        metadata.validate().err().map(|error| error.reason()),
        Some(Reason::InvalidPkce)
    );
}

#[test]
fn metadata_rejects_duplicate_json_members() {
    let result = AuthorizationServerMetadata::parse_json(
        r#"{"issuer":"https://as.example","issuer":"https://attacker.example"}"#,
    );

    assert_eq!(
        result.err().map(|error| error.reason()),
        Some(Reason::InvalidJson)
    );
}

#[test]
fn attestation_client_auth_headers_are_draft_names() -> Result<(), OauthError> {
    let pop = AttestationPopRequest {
        audience: "https://as.example".to_owned(),
        jti: "pop-1".to_owned(),
        iat: 1_700_000_000,
        challenge: Some("challenge".to_owned()),
    }
    .sign(&TestSigner)?;
    let (_header, claims, _signature): (Value, Value, Vec<u8>) = decode_compact_jwt(&pop)?;
    assert_eq!(claims.get("aud").and_then(Value::as_str), Some("https://as.example"));
    assert_eq!(claims.get("jti").and_then(Value::as_str), Some("pop-1"));
    assert!(claims.get("iss").is_none());
    let attestation = client_attestation(test_client_instance_jwk("header-test-x"))?;
    let auth = AttestationClientAuthentication::new(
        attestation.as_str().to_owned(),
        pop.as_str().to_owned(),
    )?;
    let headers = auth.headers()?;
    assert_eq!(headers[0].0, OAUTH_CLIENT_ATTESTATION_HEADER);
    assert_eq!(headers[1].0, OAUTH_CLIENT_ATTESTATION_POP_HEADER);
    Ok(())
}

#[test]
fn compact_jwt_decode_rejects_duplicate_json_members_at_every_depth() -> Result<(), OauthError> {
    let duplicate_header =
        compact_jwt_from_raw_json(r#"{"alg":"ES256","alg":"ES384"}"#, r#"{"sub":"wallet"}"#)?;
    let duplicate_nested_claim = compact_jwt_from_raw_json(
        r#"{"alg":"ES256"}"#,
        r#"{"cnf":{"jwk":{"kty":"EC","kty":"RSA"}}}"#,
    )?;

    for jwt in [duplicate_header, duplicate_nested_claim] {
        let result: Result<(Value, Value, Vec<u8>), OauthError> = decode_compact_jwt(&jwt);
        assert_eq!(
            result.err().map(|error| error.reason()),
            Some(Reason::InvalidJson)
        );
    }
    Ok(())
}

#[test]
fn compact_jwt_decode_rejects_noncanonical_base64url() -> Result<(), OauthError> {
    let canonical = compact_jwt_from_raw_json(r#"{"alg":"ES256"}"#, r#"{"sub":"wallet"}"#)?;
    let noncanonical = CompactJwt::new(format!("{}=", canonical.as_str()))?;
    let result: Result<(Value, Value, Vec<u8>), OauthError> = decode_compact_jwt(&noncanonical);

    assert_eq!(
        result.err().map(|error| error.reason()),
        Some(Reason::InvalidJson)
    );
    Ok(())
}

#[test]
fn proof_headers_reject_unprocessed_jose_parameters() -> Result<(), OauthError> {
    let pop = compact_jwt_from_raw_json(
        r#"{"typ":"oauth-client-attestation-pop+jwt","alg":"ES256","crit":["b64"],"b64":false}"#,
        r#"{"aud":"https://as.example","jti":"pop","iat":1700000000}"#,
    )?;
    let pop_result: Result<
        (
            reallyme_openid_oauth::attestation_client_auth::AttestationPopHeader,
            Value,
            Vec<u8>,
        ),
        OauthError,
    > = decode_compact_jwt(&pop);
    assert_eq!(
        pop_result.err().map(|error| error.reason()),
        Some(Reason::InvalidJson)
    );

    let dpop = DpopProof::new(
        compact_jwt_from_raw_json(
            r#"{"typ":"dpop+jwt","alg":"ES256","jwk":{"kty":"EC","crv":"P-256","x":"x","y":"y"},"x5u":"https://keys.example/cert.pem"}"#,
            r#"{"jti":"proof","htm":"POST","htu":"https://as.example/token","iat":1700000000}"#,
        )?
        .as_str()
        .to_owned(),
    )?;
    let result = dpop.validate(
        &DpopValidationContext {
            method: "POST".to_owned(),
            target_uri: "https://as.example/token".to_owned(),
            access_token: None,
            nonce: None,
            earliest_iat: 1_699_999_990,
            latest_iat: 1_700_000_010,
            confirmed_jkt: None,
        },
        &TestVerifier::new(),
    );
    assert_eq!(
        result.err().map(|error| error.reason()),
        Some(Reason::InvalidJson)
    );
    Ok(())
}

#[test]
fn attestation_client_authentication_validation_enforces_replay_hook() -> Result<(), OauthError> {
    let public_jwk = test_client_instance_jwk("bound-key-x");
    let key_thumbprint = jwk_thumbprint(&public_jwk)?;
    let pop = AttestationPopRequest {
        audience: "https://as.example".to_owned(),
        jti: "pop-1".to_owned(),
        iat: 1_700_000_000,
        challenge: Some("challenge".to_owned()),
    }
    .sign(&KeyBoundSigner {
        key_thumbprint: key_thumbprint.clone(),
    })?;
    let attestation = client_attestation(public_jwk)?;
    let auth = AttestationClientAuthentication::new(
        attestation.as_str().to_owned(),
        pop.as_str().to_owned(),
    )?;
    let verifier = KeyBoundAttestationVerifier::new();
    let verified = validate_attestation_client_authentication(
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
    )?;
    assert_eq!(verified.client_id(), "wallet-client");
    assert_eq!(verified.pop_claims.jti, "pop-1");
    assert_eq!(verified.client_instance_key_thumbprint(), key_thumbprint);
    assert_eq!(
        verified.trust_evidence().decision_evidence().purpose,
        TrustPurpose::WalletAttestationIssuer
    );
    assert_eq!(verified.client_attestation_sha256().len(), 32);
    assert_eq!(verified.pop_jti_sha256().len(), 32);
    let proto = verified.to_proto()?;
    assert_eq!(proto.client_attestation_sha256.len(), 32);
    assert_eq!(proto.client_instance_key_jwk_thumbprint_sha256.len(), 32);
    assert_eq!(proto.pop_jti_sha256.len(), 32);
    assert_eq!(proto.pop_issued_at_unix, 1_700_000_000);
    assert!(proto.trust.is_set());
    let proto_trust = proto
        .trust
        .as_option()
        .ok_or(OauthError::new(Reason::InvalidAttestationReceipt))?;
    // The exported receipt must not outlive the authorization server's local
    // freshness window even when the certificate remains valid for longer.
    assert_eq!(proto_trust.valid_until_unix, 1_700_000_030);
    assert_eq!(proto_trust.signer_spki_sha256.len(), 32);
    assert_eq!(proto_trust.anchor_certificate_sha256.len(), 32);
    assert_eq!(proto_trust.selected_path_certificate_sha256.len(), 1);
    assert_eq!(proto_trust.selected_path_certificate_sha256[0].len(), 32);
    assert_eq!(
        verified.trust_evidence().anchor_certificate_sha256(),
        proto_trust.anchor_certificate_sha256.as_slice()
    );
    assert_eq!(
        verified
            .trust_evidence()
            .selected_path_certificate_sha256()
            .len(),
        1
    );
    assert!(verifier.pop_signature_checked.get());
    assert!(verifier.replay_checked.get());
    Ok(())
}

#[test]
fn attestation_client_authentication_rejects_pop_signed_by_different_key() -> Result<(), OauthError>
{
    let attested_jwk = test_client_instance_jwk("attested-key-x");
    let different_jwk = test_client_instance_jwk("different-key-x");
    let pop = AttestationPopRequest {
        audience: "https://as.example".to_owned(),
        jti: "pop-mismatched-key".to_owned(),
        iat: 1_700_000_000,
        challenge: Some("challenge".to_owned()),
    }
    .sign(&KeyBoundSigner {
        key_thumbprint: jwk_thumbprint(&different_jwk)?,
    })?;
    let attestation = client_attestation(attested_jwk)?;
    let auth = AttestationClientAuthentication::new(
        attestation.as_str().to_owned(),
        pop.as_str().to_owned(),
    )?;
    let verifier = KeyBoundAttestationVerifier::new();

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
        Some(Reason::AttestationKeyBindingFailed)
    );
    assert!(verifier.pop_signature_checked.get());
    assert!(!verifier.replay_checked.get());
    Ok(())
}

#[test]
fn attestation_client_authentication_rejects_receipt_for_a_different_jwt() -> Result<(), OauthError>
{
    let attestation = client_attestation(test_client_instance_jwk("bound-key-x"))?;
    let other_attestation = client_attestation(test_client_instance_jwk("other-key-x"))?;
    let pop = AttestationPopRequest {
        audience: "https://as.example".to_owned(),
        jti: "pop-receipt-mismatch".to_owned(),
        iat: 1_700_000_000,
        challenge: Some("challenge".to_owned()),
    }
    .sign(&TestSigner)?;
    let auth = AttestationClientAuthentication::new(
        attestation.as_str().to_owned(),
        pop.as_str().to_owned(),
    )?;
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
        &MismatchedReceiptVerifier { other_attestation },
    );
    assert_eq!(
        result.err().map(|error| error.reason()),
        Some(Reason::InvalidAttestationReceipt)
    );
    Ok(())
}

#[test]
fn attestation_client_authentication_rejects_noncurrent_trust_receipts() -> Result<(), OauthError> {
    const CURRENT_TIME: i64 = 1_700_000_000;
    let cases = [
        (
            CURRENT_TIME - 100,
            CURRENT_TIME - 1,
            Reason::AttestationTrustEvidenceStale,
        ),
        (
            CURRENT_TIME + 1,
            CURRENT_TIME + 100,
            Reason::AttestationTrustEvidenceFutureIssued,
        ),
        (
            CURRENT_TIME - 31,
            CURRENT_TIME + 100,
            Reason::AttestationTrustEvidenceStale,
        ),
    ];
    for (evaluated_at_unix, valid_until_unix, expected_reason) in cases {
        let pop = AttestationPopRequest {
            audience: "https://as.example".to_owned(),
            jti: "pop-trust-freshness".to_owned(),
            iat: CURRENT_TIME,
            challenge: Some("challenge".to_owned()),
        }
        .sign(&TestSigner)?;
        let client_attestation =
            client_attestation(test_client_instance_jwk("trust-freshness-key"))?;
        let authentication = AttestationClientAuthentication::new(
            client_attestation.as_str().to_owned(),
            pop.as_str().to_owned(),
        )?;
        let result = validate_attestation_client_authentication(
            &authentication,
            &AttestationClientAuthenticationValidationContext {
                expected_audience: "https://as.example".to_owned(),
                expected_challenge: Some("challenge".to_owned()),
                earliest_iat: CURRENT_TIME - 10,
                latest_iat: CURRENT_TIME + 10,
                current_time: CURRENT_TIME,
                max_trust_evidence_age_seconds: 30,
            },
            &TimedTrustReceiptVerifier {
                evaluated_at_unix,
                valid_until_unix,
            },
        );
        assert_eq!(
            result.err().map(|error| error.reason()),
            Some(expected_reason)
        );
    }
    Ok(())
}

#[test]
fn attestation_client_authentication_rejects_unsafe_trust_freshness_configuration() {
    for max_trust_evidence_age_seconds in [0, MAX_ATTESTATION_TRUST_EVIDENCE_AGE_SECONDS + 1] {
        let context = AttestationClientAuthenticationValidationContext {
            expected_audience: "https://as.example".to_owned(),
            expected_challenge: Some("challenge".to_owned()),
            earliest_iat: 1_699_999_990,
            latest_iat: 1_700_000_010,
            current_time: 1_700_000_000,
            max_trust_evidence_age_seconds,
        };

        assert_eq!(
            context.validate().err().map(|error| error.reason()),
            Some(Reason::InvalidClientAttestation)
        );
    }
}

#[test]
fn attestation_trust_receipt_preserves_rejected_and_indeterminate_outcomes() {
    assert_eq!(
        WalletAttestationTrustEvidence::from_trust_decision(&attestation_trust_decision(
            TrustOutcome::Rejected,
        ))
        .err()
        .map(|error| error.reason()),
        Some(Reason::AttestationTrustRejected)
    );
    assert_eq!(
        WalletAttestationTrustEvidence::from_trust_decision(&attestation_trust_decision(
            TrustOutcome::Indeterminate,
        ))
        .err()
        .map(|error| error.reason()),
        Some(Reason::AttestationTrustIndeterminate)
    );
}

#[test]
fn attestation_trust_receipt_rejects_inconsistent_path_evidence() {
    let mut missing_status = attestation_trust_decision(TrustOutcome::Trusted);
    missing_status.evidence.certificate_status.clear();
    assert_eq!(
        WalletAttestationTrustEvidence::from_trust_decision(&missing_status)
            .err()
            .map(|error| error.reason()),
        Some(Reason::InvalidAttestationReceipt)
    );

    let mut wrong_anchor_kind = attestation_trust_decision(TrustOutcome::Trusted);
    if let Some(anchor) = wrong_anchor_kind.evidence.trust_anchor.as_mut() {
        anchor.kind = TrustAnchorKind::RootCertificate;
    }
    assert_eq!(
        WalletAttestationTrustEvidence::from_trust_decision(&wrong_anchor_kind)
            .err()
            .map(|error| error.reason()),
        Some(Reason::InvalidAttestationReceipt)
    );

    let mut wrong_position = attestation_trust_decision(TrustOutcome::Trusted);
    wrong_position.evidence.certificate_status[0].position = CertificatePosition::TrustAnchor;
    assert_eq!(
        WalletAttestationTrustEvidence::from_trust_decision(&wrong_position)
            .err()
            .map(|error| error.reason()),
        Some(Reason::InvalidAttestationReceipt)
    );

    let mut contradictory_status = attestation_trust_decision(TrustOutcome::Trusted);
    contradictory_status.evidence.certificate_status[0].status = CertificateStatus::Revoked;
    assert_eq!(
        WalletAttestationTrustEvidence::from_trust_decision(&contradictory_status)
            .err()
            .map(|error| error.reason()),
        Some(Reason::InvalidAttestationReceipt)
    );

    let mut contradictory_failure = attestation_trust_decision(TrustOutcome::Trusted);
    contradictory_failure
        .failures
        .push(reallyme_trust_core::TrustFailureReason::StatusRevoked);
    assert_eq!(
        WalletAttestationTrustEvidence::from_trust_decision(&contradictory_failure)
            .err()
            .map(|error| error.reason()),
        Some(Reason::InvalidAttestationReceipt)
    );

    let mut repeated_certificate = attestation_trust_decision(TrustOutcome::Trusted);
    if let Some(chain) = repeated_certificate.chain.as_mut() {
        if let Some(certificate) = chain.certs.first().cloned() {
            chain.certs.push(certificate);
        }
    }
    if let Some(anchor) = repeated_certificate.evidence.trust_anchor.as_mut() {
        anchor.kind = TrustAnchorKind::RootCertificate;
    }
    repeated_certificate
        .evidence
        .certificate_status
        .push(CertificateStatusEvidence {
            position: CertificatePosition::TrustAnchor,
            status: CertificateStatus::Exempt,
        });
    assert_eq!(
        WalletAttestationTrustEvidence::from_trust_decision(&repeated_certificate)
            .err()
            .map(|error| error.reason()),
        Some(Reason::InvalidAttestationReceipt)
    );
}

#[test]
fn attestation_trust_receipt_rejects_stale_and_future_evidence() -> Result<(), OauthError> {
    const CURRENT_TIME: i64 = 1_700_000_000;
    let mut stale = attestation_trust_evidence_for_times(CURRENT_TIME - 100, CURRENT_TIME - 1)?;
    assert_eq!(
        stale
            .validate_freshness_at(CURRENT_TIME, 30)
            .err()
            .map(|error| error.reason()),
        Some(Reason::AttestationTrustEvidenceStale)
    );

    let mut future = attestation_trust_evidence_for_times(CURRENT_TIME + 1, CURRENT_TIME + 100)?;
    assert_eq!(
        future
            .validate_freshness_at(CURRENT_TIME, 30)
            .err()
            .map(|error| error.reason()),
        Some(Reason::AttestationTrustEvidenceFutureIssued)
    );

    let mut current = attestation_trust_evidence_for_times(CURRENT_TIME - 10, CURRENT_TIME + 100)?;
    current.validate_freshness_at(CURRENT_TIME, 30)?;
    assert_eq!(current.valid_until_unix(), CURRENT_TIME + 20);
    Ok(())
}

#[test]
fn attestation_trust_receipt_expires_with_the_earliest_path_certificate() -> Result<(), OauthError>
{
    const EVALUATED_AT: i64 = 1_700_000_000;
    const ROOT_EXPIRY: i64 = EVALUATED_AT + 40;
    let mut decision = attestation_trust_decision(TrustOutcome::Trusted);
    let chain = decision
        .chain
        .as_mut()
        .ok_or(OauthError::new(Reason::InvalidAttestationReceipt))?;
    let mut root = chain
        .certs
        .first()
        .cloned()
        .ok_or(OauthError::new(Reason::InvalidAttestationReceipt))?;
    root.der = vec![0x30, 0x01];
    root.spki_der = vec![5, 6, 7, 8];
    root.not_after = time::OffsetDateTime::from_unix_timestamp(ROOT_EXPIRY)
        .map_err(|_| OauthError::new(Reason::InvalidAttestationReceipt))?;
    chain.certs.push(root);
    decision
        .evidence
        .certificate_status
        .push(CertificateStatusEvidence {
            position: CertificatePosition::TrustAnchor,
            status: CertificateStatus::Exempt,
        });
    decision
        .evidence
        .trust_anchor
        .as_mut()
        .ok_or(OauthError::new(Reason::InvalidAttestationReceipt))?
        .kind = TrustAnchorKind::RootCertificate;

    let evidence = WalletAttestationTrustEvidence::from_trust_decision(&decision)?;
    assert_eq!(evidence.valid_until_unix(), ROOT_EXPIRY);
    Ok(())
}
