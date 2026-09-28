// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! RFC 9449 DPoP target-URI normalization and binding tests.

use std::cell::Cell;

use reallyme_openid_oauth::jwt::sign_compact_jwt;
use reallyme_openid_oauth::{
    jwk_thumbprint, DpopClaims, DpopHeader, DpopProof, DpopProofRequest, DpopValidationContext,
    DpopVerifier, JwtSigner, OauthError, Reason,
};
use serde_json::{json, Value};

const ISSUED_AT: i64 = 1_700_000_000;
const ACCESS_TOKEN: &str = "access-token";

struct EchoSigner;

impl JwtSigner for EchoSigner {
    fn algorithm(&self) -> &str {
        "ES256"
    }

    fn sign(&self, signing_input: &[u8]) -> Result<Vec<u8>, OauthError> {
        Ok(signing_input.to_vec())
    }
}

struct PolicyVerifier {
    replay_checked: Cell<bool>,
    reject_replay: bool,
}

impl PolicyVerifier {
    fn accepting() -> Self {
        Self {
            replay_checked: Cell::new(false),
            reject_replay: false,
        }
    }

    fn rejecting_replay() -> Self {
        Self {
            replay_checked: Cell::new(false),
            reject_replay: true,
        }
    }
}

impl DpopVerifier for PolicyVerifier {
    fn verify_signature(
        &self,
        _protected_header: &Value,
        signing_input: &[u8],
        signature: &[u8],
    ) -> Result<(), OauthError> {
        if signature == signing_input {
            Ok(())
        } else {
            Err(OauthError::new(Reason::VerificationFailed))
        }
    }

    fn check_replay(&self, _jti: &str, _iat: i64) -> Result<(), OauthError> {
        self.replay_checked.set(true);
        if self.reject_replay {
            Err(OauthError::new(Reason::DpopReplay))
        } else {
            Ok(())
        }
    }
}

fn public_jwk() -> Value {
    json!({
        "kty": "EC",
        "crv": "P-256",
        "x": "axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY",
        "y": "T-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU",
    })
}

fn proof_with_claimed_htu(htu: &str, jti: &str) -> Result<DpopProof, OauthError> {
    let header = DpopHeader::new("ES256".to_owned(), public_jwk())?;
    let claims = DpopClaims {
        jti: jti.to_owned(),
        htm: "POST".to_owned(),
        htu: htu.to_owned(),
        iat: ISSUED_AT,
        ath: None,
        nonce: None,
    };
    let compact = sign_compact_jwt(&header, &claims, &EchoSigner)?;
    DpopProof::new(compact.as_str().to_owned())
}

fn proof_request(target_uri: &str, jti: &str, access_token: Option<&str>) -> DpopProofRequest {
    DpopProofRequest {
        method: "POST".to_owned(),
        target_uri: target_uri.to_owned(),
        jti: jti.to_owned(),
        iat: ISSUED_AT,
        public_jwk: public_jwk(),
        access_token: access_token.map(str::to_owned),
        nonce: None,
    }
}

fn validation_context(
    target_uri: &str,
    access_token: Option<&str>,
    confirmed_jkt: Option<String>,
) -> DpopValidationContext {
    DpopValidationContext {
        method: "POST".to_owned(),
        target_uri: target_uri.to_owned(),
        access_token: access_token.map(str::to_owned),
        nonce: None,
        earliest_iat: ISSUED_AT - 10,
        latest_iat: ISSUED_AT + 10,
        confirmed_jkt,
    }
}

fn error_reason<T>(result: Result<T, OauthError>) -> Option<Reason> {
    result.err().map(|error| error.reason())
}

#[test]
fn signed_proofs_ignore_query_fragment_or_both_during_htu_matching() -> Result<(), OauthError> {
    let cases = [
        (
            "https://as.example/token?proof=value",
            "https://as.example/token?request=other",
        ),
        (
            "https://as.example/token#proof-fragment",
            "https://as.example/token#request-fragment",
        ),
        (
            "https://as.example/token?proof=value#proof-fragment",
            "https://as.example/token?request=other#request-fragment",
        ),
    ];

    for (index, (claimed_htu, request_target)) in cases.into_iter().enumerate() {
        let proof = proof_with_claimed_htu(claimed_htu, &format!("component-case-{index}"))?;
        proof.validate(
            &validation_context(request_target, None, None),
            &PolicyVerifier::accepting(),
        )?;
    }
    Ok(())
}

#[test]
fn proof_generation_omits_query_and_fragment_from_htu() -> Result<(), OauthError> {
    let proof = proof_request(
        "https://as.example/token?request=value#client-state",
        "generation-normalization",
        None,
    )
    .sign(&EchoSigner)?;

    proof.validate(
        &validation_context("https://as.example/token", None, None),
        &PolicyVerifier::accepting(),
    )
}

#[test]
fn dpop_htu_rejects_mismatched_scheme_host_and_path() -> Result<(), OauthError> {
    let proof = proof_with_claimed_htu("https://as.example/token", "target-mismatch")?;

    assert_eq!(
        error_reason(proof.validate(
            &validation_context("http://as.example/token", None, None),
            &PolicyVerifier::accepting(),
        )),
        Some(Reason::InvalidUrl)
    );
    for target in [
        "https://other.example/token",
        "https://as.example/other-path",
    ] {
        assert_eq!(
            error_reason(proof.validate(
                &validation_context(target, None, None),
                &PolicyVerifier::accepting(),
            )),
            Some(Reason::InvalidDpopProof),
            "{target}"
        );
    }
    let insecure_proof = proof_with_claimed_htu("http://as.example/token", "scheme-mismatch")?;
    assert_eq!(
        error_reason(insecure_proof.validate(
            &validation_context("https://as.example/token", None, None),
            &PolicyVerifier::accepting(),
        )),
        Some(Reason::InvalidUrl)
    );
    Ok(())
}

#[test]
fn signed_proofs_reject_userinfo_backslashes_and_malformed_htu() -> Result<(), OauthError> {
    for (index, target) in [
        "https://user@as.example/token",
        "https://user:secret@as.example/token",
        "https://as.example\\@other.example/token",
        "https://as.example/\\other",
        "https://",
        "not a URL",
    ]
    .into_iter()
    .enumerate()
    {
        let proof = proof_with_claimed_htu(target, &format!("malformed-htu-{index}"))?;
        assert_eq!(
            error_reason(proof.validate(
                &validation_context("https://as.example/token", None, None),
                &PolicyVerifier::accepting(),
            )),
            Some(Reason::InvalidUrl),
            "{target}"
        );
    }
    Ok(())
}

#[test]
fn dpop_validation_propagates_replay_rejection() -> Result<(), OauthError> {
    let proof =
        proof_request("https://as.example/token", "replayed-proof", None).sign(&EchoSigner)?;
    let verifier = PolicyVerifier::rejecting_replay();

    assert_eq!(
        error_reason(proof.validate(
            &validation_context("https://as.example/token", None, None),
            &verifier,
        )),
        Some(Reason::DpopReplay)
    );
    assert!(verifier.replay_checked.get());
    Ok(())
}

#[test]
fn dpop_validation_rejects_ath_and_cnf_jkt_mismatches() -> Result<(), OauthError> {
    let key = public_jwk();
    let matching_jkt = jwk_thumbprint(&key)?;
    let proof = proof_request(
        "https://resource.example/records?view=summary#top",
        "token-binding",
        Some(ACCESS_TOKEN),
    )
    .sign(&EchoSigner)?;

    assert_eq!(
        error_reason(proof.validate(
            &validation_context(
                "https://resource.example/records",
                Some("different-access-token"),
                Some(matching_jkt.clone()),
            ),
            &PolicyVerifier::accepting(),
        )),
        Some(Reason::InvalidDpopProof)
    );
    assert_eq!(
        error_reason(proof.validate(
            &validation_context(
                "https://resource.example/records",
                Some(ACCESS_TOKEN),
                Some("different-proof-key".to_owned()),
            ),
            &PolicyVerifier::accepting(),
        )),
        Some(Reason::InvalidDpopProof)
    );

    proof.validate(
        &validation_context(
            "https://resource.example/records?other=value#ignored",
            Some(ACCESS_TOKEN),
            Some(matching_jkt),
        ),
        &PolicyVerifier::accepting(),
    )
}
