// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! OAuth client response policy tests.

use reallyme_openid_oauth::{
    evaluate_dpop_nonce_response, parse_attestation_challenge_header,
    parse_attestation_challenge_response, validate_authorization_response_issuer,
    AuthorizationResponseIssuerPolicy, DpopNonceDecision, DpopNonceEndpoint, OauthError, Reason,
};

fn reason<T>(result: Result<T, OauthError>) -> Option<Reason> {
    result.err().map(|error| error.reason())
}

#[test]
fn parses_uncacheable_attestation_challenge_with_extensions() -> Result<(), OauthError> {
    let challenge = parse_attestation_challenge_response(
        200,
        "application/json; charset=utf-8",
        &["private, no-store"],
        br#"{"attestation_challenge":"AYjcyMzY3ZDhiNmJkNTZ","future":true}"#,
    )?;
    assert_eq!(challenge.as_str(), "AYjcyMzY3ZDhiNmJkNTZ");
    Ok(())
}

#[test]
fn rejects_ambiguous_or_cacheable_attestation_challenge_responses() {
    let cases: &[(u16, &str, &[&str], &[u8])] = &[
        (
            201,
            "application/json",
            &["no-store"],
            br#"{"attestation_challenge":"challenge"}"#,
        ),
        (
            200,
            "text/plain",
            &["no-store"],
            br#"{"attestation_challenge":"challenge"}"#,
        ),
        (
            200,
            "application/json",
            &["private"],
            br#"{"attestation_challenge":"challenge"}"#,
        ),
        (
            200,
            "application/json",
            &["no-store"],
            br#"{"attestation_challenge":"first","attestation_challenge":"second"}"#,
        ),
        (200, "application/json", &["no-store"], br#"{}"#),
    ];

    for (status, content_type, cache_control, body) in cases {
        assert_eq!(
            reason(parse_attestation_challenge_response(
                *status,
                content_type,
                cache_control,
                body,
            )),
            Some(Reason::InvalidAttestationChallengeResponse)
        );
    }
}

#[test]
fn challenge_header_requires_exactly_one_value() -> Result<(), OauthError> {
    assert_eq!(
        parse_attestation_challenge_header(&["fresh-challenge"])?.as_str(),
        "fresh-challenge"
    );
    assert_eq!(
        reason(parse_attestation_challenge_header(&[])),
        Some(Reason::InvalidAttestationChallengeResponse)
    );
    assert_eq!(
        reason(parse_attestation_challenge_header(&["one", "two"])),
        Some(Reason::InvalidAttestationChallengeResponse)
    );
    Ok(())
}

#[test]
fn authorization_server_dpop_challenge_permits_one_retry() -> Result<(), OauthError> {
    let decision = evaluate_dpop_nonce_response(
        DpopNonceEndpoint::AuthorizationServer,
        400,
        Some("use_dpop_nonce"),
        &["opaque.nonce"],
        false,
    )?;
    assert_eq!(
        decision,
        DpopNonceDecision {
            nonce: Some("opaque.nonce"),
            retry: true,
        }
    );
    assert_eq!(
        reason(evaluate_dpop_nonce_response(
            DpopNonceEndpoint::AuthorizationServer,
            400,
            Some("use_dpop_nonce"),
            &["opaque.nonce"],
            true,
        )),
        Some(Reason::DpopNonceRetryExhausted)
    );
    Ok(())
}

#[test]
fn resource_server_dpop_challenge_requires_401_and_parsed_dpop_error() {
    assert_eq!(
        evaluate_dpop_nonce_response(
            DpopNonceEndpoint::ResourceServer,
            401,
            Some("use_dpop_nonce"),
            &["resource-nonce"],
            false,
        ),
        Ok(DpopNonceDecision {
            nonce: Some("resource-nonce"),
            retry: true,
        })
    );
    assert_eq!(
        evaluate_dpop_nonce_response(
            DpopNonceEndpoint::ResourceServer,
            400,
            Some("use_dpop_nonce"),
            &["resource-nonce"],
            false,
        ),
        Ok(DpopNonceDecision {
            nonce: Some("resource-nonce"),
            retry: false,
        })
    );
}

#[test]
fn dpop_nonce_response_rejects_missing_duplicate_and_invalid_nonce_values() {
    assert_eq!(
        reason(evaluate_dpop_nonce_response(
            DpopNonceEndpoint::AuthorizationServer,
            400,
            Some("use_dpop_nonce"),
            &[],
            false,
        )),
        Some(Reason::InvalidDpopNonceResponse)
    );
    assert_eq!(
        reason(evaluate_dpop_nonce_response(
            DpopNonceEndpoint::AuthorizationServer,
            400,
            Some("use_dpop_nonce"),
            &["one", "two"],
            false,
        )),
        Some(Reason::InvalidDpopNonceResponse)
    );
    assert_eq!(
        reason(evaluate_dpop_nonce_response(
            DpopNonceEndpoint::AuthorizationServer,
            200,
            None,
            &["contains space"],
            false,
        )),
        Some(Reason::InvalidDpopNonceResponse)
    );
}

#[test]
fn successful_response_updates_nonce_without_replaying_request() {
    assert_eq!(
        evaluate_dpop_nonce_response(
            DpopNonceEndpoint::AuthorizationServer,
            200,
            None,
            &["next-nonce"],
            false,
        ),
        Ok(DpopNonceDecision {
            nonce: Some("next-nonce"),
            retry: false,
        })
    );
}

#[test]
fn rfc9207_requires_and_compares_advertised_issuer() -> Result<(), OauthError> {
    validate_authorization_response_issuer(
        "https://as.example",
        true,
        &["https://as.example"],
        AuthorizationResponseIssuerPolicy::MetadataDrivenStrict,
    )?;
    assert_eq!(
        reason(validate_authorization_response_issuer(
            "https://as.example",
            true,
            &[],
            AuthorizationResponseIssuerPolicy::MetadataDrivenStrict,
        )),
        Some(Reason::AuthorizationResponseIssuerRequired)
    );
    assert_eq!(
        reason(validate_authorization_response_issuer(
            "https://as.example",
            true,
            &["https://other.example"],
            AuthorizationResponseIssuerPolicy::MetadataDrivenStrict,
        )),
        Some(Reason::AuthorizationServerIssuerMismatch)
    );
    Ok(())
}

#[test]
fn rfc9207_unadvertised_issuer_behavior_is_explicit_policy() -> Result<(), OauthError> {
    validate_authorization_response_issuer(
        "https://as.example",
        false,
        &[],
        AuthorizationResponseIssuerPolicy::MetadataDrivenStrict,
    )?;
    assert_eq!(
        reason(validate_authorization_response_issuer(
            "https://as.example",
            false,
            &["https://as.example"],
            AuthorizationResponseIssuerPolicy::MetadataDrivenStrict,
        )),
        Some(Reason::AuthorizationResponseIssuerUnexpected)
    );
    validate_authorization_response_issuer(
        "https://as.example",
        false,
        &["https://as.example"],
        AuthorizationResponseIssuerPolicy::AllowUnadvertisedExact,
    )?;
    assert_eq!(
        reason(validate_authorization_response_issuer(
            "https://as.example",
            false,
            &["https://as.example", "https://as.example"],
            AuthorizationResponseIssuerPolicy::AllowUnadvertisedExact,
        )),
        Some(Reason::AuthorizationServerIssuerMismatch)
    );
    Ok(())
}

#[test]
fn invalid_challenge_strings_return_fixed_errors() {
    for body in [
        br#"{"attestation_challenge":""}"#.as_slice(),
        br#"{"attestation_challenge":"secret\u0000value"}"#.as_slice(),
    ] {
        assert_eq!(
            reason(parse_attestation_challenge_response(
                200,
                "application/json",
                &["no-store"],
                body,
            )),
            Some(Reason::InvalidAttestationChallengeResponse),
        );
    }
}
