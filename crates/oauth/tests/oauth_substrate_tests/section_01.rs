// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::cell::Cell;
use std::collections::BTreeMap;

use envelopes_x509::{BasicConstraints, KeyUsage, X509Certificate, X509Chain};
use reallyme_codec::base64url::bytes_to_base64url;
use reallyme_openid_oauth::jwt::{decode_compact_jwt, sign_compact_jwt};
use reallyme_openid_oauth::{
    jwk_thumbprint, validate_attestation_client_authentication, AttestationClientAuthentication,
    AttestationClientAuthenticationValidationContext, AttestationClientAuthenticationVerifier,
    AttestationPopRequest, AttestedClientKey, AuthorizationServerMetadata, CodeChallengeMethod,
    CompactJwt, DpopHeader, DpopProof, DpopProofRequest, DpopValidationContext, DpopVerifier,
    GrantType, JwtSigner, JwtVerifier, OauthError, ParRequest, PkceVerifier, Reason,
    VerifiedAttestationClientAuthentication, VerifiedClientAttestation,
    WalletAttestationTrustEvidence, MAX_ATTESTATION_TRUST_EVIDENCE_AGE_SECONDS,
    OAUTH_CLIENT_ATTESTATION_HEADER, OAUTH_CLIENT_ATTESTATION_POP_HEADER,
};
use reallyme_trust_core::{
    CertificatePosition, CertificateStatus, CertificateStatusEvidence, TrustAnchorEvidence,
    TrustAnchorKind, TrustDecision, TrustEvidence, TrustOutcome, TrustPolicyId, TrustPurpose,
    TrustSourceEvidence,
};
use secrecy::SecretString;
use serde::Deserialize;
use serde_json::{json, Value};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Debug, Deserialize)]
struct JwkThumbprintVectorSuite {
    cases: Vec<JwkThumbprintVectorCase>,
}

#[derive(Debug, Deserialize)]
struct JwkThumbprintVectorCase {
    id: String,
    jwk: Value,
    expected_thumbprint: Option<String>,
    expected_error: Option<String>,
}

struct TestSigner;

impl JwtSigner for TestSigner {
    fn algorithm(&self) -> &str {
        "ES256"
    }

    fn sign(&self, signing_input: &[u8]) -> Result<Vec<u8>, OauthError> {
        Ok(signing_input.to_vec())
    }
}

struct TestVerifier {
    replay_checked: Cell<bool>,
    pop_signature_checked: Cell<bool>,
}

impl TestVerifier {
    fn new() -> Self {
        Self {
            replay_checked: Cell::new(false),
            pop_signature_checked: Cell::new(false),
        }
    }
}

impl JwtVerifier for TestVerifier {
    fn verify(
        &self,
        _protected_header: &serde_json::Value,
        _signing_input: &[u8],
        _signature: &[u8],
    ) -> Result<(), OauthError> {
        Ok(())
    }
}

impl DpopVerifier for TestVerifier {
    fn verify_signature(
        &self,
        protected_header: &serde_json::Value,
        signing_input: &[u8],
        signature: &[u8],
    ) -> Result<(), OauthError> {
        self.verify(protected_header, signing_input, signature)
    }

    fn check_replay(&self, _jti: &str, _iat: i64) -> Result<(), OauthError> {
        self.replay_checked.set(true);
        Ok(())
    }
}

impl AttestationClientAuthenticationVerifier for TestVerifier {
    fn verify_client_attestation(
        &self,
        _client_attestation: &CompactJwt,
    ) -> Result<WalletAttestationTrustEvidence, OauthError> {
        trusted_attestation_evidence()
    }

    fn verify_pop_signature(
        &self,
        _verified_attestation: &VerifiedClientAttestation,
        protected_header: &serde_json::Value,
        signing_input: &[u8],
        signature: &[u8],
    ) -> Result<(), OauthError> {
        self.pop_signature_checked.set(true);
        self.verify(protected_header, signing_input, signature)
    }

    fn check_replay(
        &self,
        _verified_attestation: &VerifiedClientAttestation,
        _jti: &str,
        _iat: i64,
    ) -> Result<(), OauthError> {
        self.replay_checked.set(true);
        Ok(())
    }
}

struct KeyBoundSigner {
    key_thumbprint: String,
}

impl JwtSigner for KeyBoundSigner {
    fn algorithm(&self) -> &str {
        "ES256"
    }

    fn sign(&self, _signing_input: &[u8]) -> Result<Vec<u8>, OauthError> {
        Ok(self.key_thumbprint.as_bytes().to_vec())
    }
}

struct KeyBoundAttestationVerifier {
    replay_checked: Cell<bool>,
    pop_signature_checked: Cell<bool>,
}

struct MismatchedReceiptVerifier {
    other_attestation: CompactJwt,
}

struct TimedTrustReceiptVerifier {
    evaluated_at_unix: i64,
    valid_until_unix: i64,
}

impl AttestationClientAuthenticationVerifier for TimedTrustReceiptVerifier {
    fn verify_client_attestation(
        &self,
        client_attestation: &CompactJwt,
    ) -> Result<WalletAttestationTrustEvidence, OauthError> {
        let _ = client_attestation;
        attestation_trust_evidence_for_times(self.evaluated_at_unix, self.valid_until_unix)
    }

    fn verify_pop_signature(
        &self,
        _verified_attestation: &VerifiedClientAttestation,
        _protected_header: &serde_json::Value,
        _signing_input: &[u8],
        _signature: &[u8],
    ) -> Result<(), OauthError> {
        Ok(())
    }

    fn check_replay(
        &self,
        _verified_attestation: &VerifiedClientAttestation,
        _jti: &str,
        _iat: i64,
    ) -> Result<(), OauthError> {
        Ok(())
    }
}

impl AttestationClientAuthenticationVerifier for MismatchedReceiptVerifier {
    fn verify_client_attestation(
        &self,
        _client_attestation: &CompactJwt,
    ) -> Result<WalletAttestationTrustEvidence, OauthError> {
        let _ = &self.other_attestation;
        Err(OauthError::new(Reason::InvalidAttestationReceipt))
    }

    fn verify_pop_signature(
        &self,
        _verified_attestation: &VerifiedClientAttestation,
        _protected_header: &serde_json::Value,
        _signing_input: &[u8],
        _signature: &[u8],
    ) -> Result<(), OauthError> {
        Err(OauthError::new(Reason::VerificationFailed))
    }

    fn check_replay(
        &self,
        _verified_attestation: &VerifiedClientAttestation,
        _jti: &str,
        _iat: i64,
    ) -> Result<(), OauthError> {
        Err(OauthError::new(Reason::VerificationFailed))
    }
}

impl KeyBoundAttestationVerifier {
    fn new() -> Self {
        Self {
            replay_checked: Cell::new(false),
            pop_signature_checked: Cell::new(false),
        }
    }
}

impl AttestationClientAuthenticationVerifier for KeyBoundAttestationVerifier {
    fn verify_client_attestation(
        &self,
        _client_attestation: &CompactJwt,
    ) -> Result<WalletAttestationTrustEvidence, OauthError> {
        trusted_attestation_evidence()
    }

    fn verify_pop_signature(
        &self,
        verified_attestation: &VerifiedClientAttestation,
        _protected_header: &serde_json::Value,
        _signing_input: &[u8],
        signature: &[u8],
    ) -> Result<(), OauthError> {
        self.pop_signature_checked.set(true);
        let attested_client_key = verified_attestation.attested_client_key();
        let key_thumbprint = jwk_thumbprint(attested_client_key.public_jwk())
            .map_err(|_| OauthError::new(Reason::VerificationFailed))?;
        if key_thumbprint != attested_client_key.thumbprint()
            || signature != key_thumbprint.as_bytes()
        {
            return Err(OauthError::new(Reason::VerificationFailed));
        }
        Ok(())
    }

    fn check_replay(
        &self,
        _verified_attestation: &VerifiedClientAttestation,
        _jti: &str,
        _iat: i64,
    ) -> Result<(), OauthError> {
        self.replay_checked.set(true);
        Ok(())
    }
}

fn trusted_attestation_evidence() -> Result<WalletAttestationTrustEvidence, OauthError> {
    let decision = attestation_trust_decision(TrustOutcome::Trusted);
    WalletAttestationTrustEvidence::from_trust_decision(&decision)
}

fn attestation_trust_decision(outcome: TrustOutcome) -> TrustDecision {
    let signer = X509Certificate {
        der: vec![0x30, 0x00],
        subject: "CN=Wallet Attestation Issuer".to_owned(),
        issuer: "CN=Wallet Attestation Root".to_owned(),
        serial: vec![1],
        not_before: time::OffsetDateTime::UNIX_EPOCH,
        not_after: time::OffsetDateTime::UNIX_EPOCH + time::Duration::days(365_000),
        spki_der: vec![1, 2, 3, 4],
        signature_algorithm_oid: "1.2.840.10045.4.3.2".to_owned(),
        basic_constraints: Some(BasicConstraints {
            ca: false,
            path_len_constraint: None,
        }),
        key_usage: Some(KeyUsage {
            digital_signature: true,
            content_commitment: false,
            key_encipherment: false,
            data_encipherment: false,
            key_cert_sign: false,
            crl_sign: false,
            key_agreement: false,
            encipher_only: false,
            decipher_only: false,
        }),
        extended_key_usage: None,
        subject_key_identifier: None,
        authority_key_identifier: None,
        san_dns: Vec::new(),
        san_ip: Vec::new(),
        certificate_policies: Vec::new(),
        qc_statements: Default::default(),
        profile: Default::default(),
    };
    TrustDecision {
        outcome,
        accepted: outcome == TrustOutcome::Trusted,
        chain: Some(X509Chain {
            certs: vec![signer],
        }),
        failures: Vec::new(),
        evidence: TrustEvidence {
            purpose: TrustPurpose::WalletAttestationIssuer,
            policy_id: TrustPolicyId::WalletAttestationIssuerV1,
            evaluated_at: time::OffsetDateTime::UNIX_EPOCH + time::Duration::seconds(1_700_000_000),
            source: Some(TrustSourceEvidence {
                source_id: [7; 32],
                snapshot_id: [8; 32],
            }),
            trust_anchor: Some(TrustAnchorEvidence {
                kind: TrustAnchorKind::DirectEndEntity,
                configured_index: 0,
            }),
            certificate_status: vec![CertificateStatusEvidence {
                position: CertificatePosition::Leaf,
                status: CertificateStatus::Good,
            }],
        },
    }
}

fn attestation_trust_evidence_for_times(
    evaluated_at_unix: i64,
    valid_until_unix: i64,
) -> Result<WalletAttestationTrustEvidence, OauthError> {
    let evaluated_at = time::OffsetDateTime::from_unix_timestamp(evaluated_at_unix)
        .map_err(|_| OauthError::new(Reason::InvalidAttestationReceipt))?;
    let valid_until = time::OffsetDateTime::from_unix_timestamp(valid_until_unix)
        .map_err(|_| OauthError::new(Reason::InvalidAttestationReceipt))?;
    let mut decision = attestation_trust_decision(TrustOutcome::Trusted);
    decision.evidence.evaluated_at = evaluated_at;
    let chain = decision
        .chain
        .as_mut()
        .ok_or(OauthError::new(Reason::InvalidAttestationReceipt))?;
    let signer = chain
        .certs
        .first_mut()
        .ok_or(OauthError::new(Reason::InvalidAttestationReceipt))?;
    signer.not_after = valid_until;
    WalletAttestationTrustEvidence::from_trust_decision(&decision)
}

fn client_attestation(public_jwk: Value) -> Result<CompactJwt, OauthError> {
    client_attestation_with_claims(json!({
        "sub": "wallet-client",
        "iat": 1_699_999_000_i64,
        "exp": 1_700_001_000_i64,
        "cnf": { "jwk": public_jwk },
    }))
}

fn client_attestation_with_claims(claims: Value) -> Result<CompactJwt, OauthError> {
    sign_compact_jwt(
        &json!({
            "typ": "oauth-client-attestation+jwt",
            "alg": "ES256",
            "kid": "attester-key",
        }),
        &claims,
        &TestSigner,
    )
}

fn test_client_instance_jwk(coordinate: &str) -> Value {
    json!({
        "kty": "EC",
        "use": "sig",
        "crv": "P-256",
        "x": coordinate,
        "y": "shared-y-coordinate",
    })
}

fn compact_jwt_from_raw_json(header: &str, payload: &str) -> Result<CompactJwt, OauthError> {
    CompactJwt::new(format!(
        "{}.{}.AA",
        bytes_to_base64url(header.as_bytes()),
        bytes_to_base64url(payload.as_bytes())
    ))
}

fn valid_authorization_server_metadata() -> AuthorizationServerMetadata {
    AuthorizationServerMetadata {
        issuer: "https://as.example".to_owned(),
        authorization_endpoint: Some("https://as.example/authorize".to_owned()),
        token_endpoint: Some("https://as.example/token".to_owned()),
        pushed_authorization_request_endpoint: Some("https://as.example/par".to_owned()),
        challenge_endpoint: Some("https://as.example/challenge".to_owned()),
        grant_types_supported: Some(vec![GrantType::AuthorizationCode]),
        response_types_supported: Some(vec!["code".to_owned()]),
        code_challenge_methods_supported: Some(vec!["S256".to_owned()]),
        dpop_signing_alg_values_supported: Some(vec!["ES256".to_owned()]),
        require_pushed_authorization_requests: Some(true),
        token_endpoint_auth_methods_supported: Some(vec!["attest_jwt_client_auth".to_owned()]),
        authorization_response_iss_parameter_supported: Some(true),
        client_attestation_signing_alg_values_supported: Some(vec!["ES256".to_owned()]),
        client_attestation_pop_signing_alg_values_supported: Some(vec!["ES256".to_owned()]),
    }
}

#[test]
fn pkce_uses_s256_only() -> Result<(), OauthError> {
    let verifier = PkceVerifier::new(SecretString::from(
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~",
    ))?;
    let challenge = verifier.challenge();
    assert_eq!(challenge.code_challenge_method, CodeChallengeMethod::S256);
    assert!(!challenge.code_challenge.is_empty());
    Ok(())
}

#[test]
fn pkce_rejects_invalid_verifier_values() {
    let short = PkceVerifier::new(SecretString::from("too-short"));
    assert_eq!(
        short.err().map(|error| error.reason()),
        Some(Reason::InvalidPkce)
    );

    let invalid_character = PkceVerifier::new(SecretString::from(
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ!",
    ));
    assert_eq!(
        invalid_character.err().map(|error| error.reason()),
        Some(Reason::InvalidPkce)
    );
}

#[test]
fn par_rejects_request_uri_parameter() {
    let mut additional_parameters = BTreeMap::new();
    additional_parameters.insert("request_uri".to_owned(), "urn:bad".to_owned());
    let request = ParRequest {
        client_id: "client".to_owned(),
        response_type: "code".to_owned(),
        redirect_uri: Some("https://wallet.example/cb".to_owned()),
        scope: None,
        state: None,
        pkce: None,
        dpop_jkt: None,
        attestation_client_authentication: None,
        additional_parameters,
    };
    assert_eq!(
        request.validate().err().map(|error| error.reason()),
        Some(Reason::InvalidParRequest)
    );
}

#[test]
fn dpop_generation_and_validation_enforces_replay_hook() -> Result<(), OauthError> {
    let proof = DpopProofRequest {
        method: "POST".to_owned(),
        target_uri: "https://as.example/token?ignored=true".to_owned(),
        jti: "jti-1".to_owned(),
        iat: 1_700_000_000,
        public_jwk: json!({"kty":"EC","crv":"P-256","x":"x","y":"y"}),
        access_token: Some("access-token".to_owned()),
        nonce: Some("nonce".to_owned()),
    }
    .sign(&TestSigner)?;
    let verifier = TestVerifier::new();
    proof.validate(
        &DpopValidationContext {
            method: "POST".to_owned(),
            target_uri: "https://as.example/token".to_owned(),
            access_token: Some("access-token".to_owned()),
            nonce: Some("nonce".to_owned()),
            earliest_iat: 1_699_999_990,
            latest_iat: 1_700_000_010,
            confirmed_jkt: None,
        },
        &verifier,
    )?;
    assert!(verifier.replay_checked.get());
    Ok(())
}

#[test]
fn dpop_validation_enforces_access_token_jkt_binding() -> Result<(), OauthError> {
    // RFC 9449 §4.3(12): a proof whose key thumbprint does not match the access
    // token's confirmed `cnf.jkt` is rejected even if everything else is valid.
    let public_jwk = json!({"kty":"EC","crv":"P-256","x":"x","y":"y"});
    let proof = DpopProofRequest {
        method: "POST".to_owned(),
        target_uri: "https://as.example/token".to_owned(),
        jti: "jti-2".to_owned(),
        iat: 1_700_000_000,
        public_jwk: public_jwk.clone(),
        access_token: Some("access-token".to_owned()),
        nonce: None,
    }
    .sign(&TestSigner)?;

    let matching_jkt = jwk_thumbprint(&public_jwk)?;
    let mut context = DpopValidationContext {
        method: "POST".to_owned(),
        target_uri: "https://as.example/token".to_owned(),
        access_token: Some("access-token".to_owned()),
        nonce: None,
        earliest_iat: 1_699_999_990,
        latest_iat: 1_700_000_010,
        confirmed_jkt: Some(matching_jkt),
    };
    proof.validate(&context, &TestVerifier::new())?;

    context.confirmed_jkt = Some("not-the-proof-key".to_owned());
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
fn dpop_validation_accepts_matching_access_token_jkt_binding() -> Result<(), OauthError> {
    let public_jwk = json!({"kty":"EC","crv":"P-256","x":"x","y":"y"});
    let proof = DpopProofRequest {
        method: "POST".to_owned(),
        target_uri: "https://as.example/token".to_owned(),
        jti: "jti-2a".to_owned(),
        iat: 1_700_000_000,
        public_jwk: public_jwk.clone(),
        access_token: Some("access-token".to_owned()),
        nonce: None,
    }
    .sign(&TestSigner)?;

    proof.validate(
        &DpopValidationContext {
            method: "POST".to_owned(),
            target_uri: "https://as.example/token".to_owned(),
            access_token: Some("access-token".to_owned()),
            nonce: None,
            earliest_iat: 1_699_999_990,
            latest_iat: 1_700_000_010,
            confirmed_jkt: Some(jwk_thumbprint(&public_jwk)?),
        },
        &TestVerifier::new(),
    )
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
