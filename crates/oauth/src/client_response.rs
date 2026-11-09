// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Pure OAuth client decisions for security-sensitive HTTP responses.

use serde_json::Value;
use zeroize::Zeroizing;

use crate::error::{OauthError, OauthResult, Reason};
use crate::sensitive::zeroize_json_value;
use crate::strict_json::validate_strict_json;
use crate::validation::{validate_issuer_identifier, validate_token, MAX_JSON_BYTES};

const HTTP_STATUS_OK: u16 = 200;
const HTTP_STATUS_BAD_REQUEST: u16 = 400;
const HTTP_STATUS_UNAUTHORIZED: u16 = 401;
const USE_DPOP_NONCE: &str = "use_dpop_nonce";
const APPLICATION_JSON: &str = "application/json";
const ATTESTATION_CHALLENGE_MEMBER: &str = "attestation_challenge";

/// Server-provided client-attestation challenge with zeroizing ownership.
pub struct AttestationChallenge {
    value: Zeroizing<String>,
}

impl AttestationChallenge {
    /// Borrows the opaque challenge for construction of the next PoP JWT.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.value.as_str()
    }
}

/// Endpoint class that supplied a DPoP nonce.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum DpopNonceEndpoint {
    /// OAuth Authorization Server endpoint such as PAR or token.
    AuthorizationServer,
    /// OAuth-protected Resource Server endpoint.
    ResourceServer,
}

/// Result of classifying a response that may carry a DPoP nonce.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DpopNonceDecision<'a> {
    /// New nonce to retain for this exact server, if one was supplied.
    pub nonce: Option<&'a str>,
    /// Whether the failed request may be retried once with a fresh DPoP proof.
    pub retry: bool,
}

/// Local policy for RFC 9207 when metadata does not advertise `iss` support.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum AuthorizationResponseIssuerPolicy {
    /// Follow metadata strictly: require advertised `iss` and reject an unadvertised one.
    MetadataDrivenStrict,
    /// Require one exact issuer parameter regardless of metadata advertisement.
    RequireExact,
    /// Accept an absent unadvertised parameter or an exact one.
    AllowUnadvertisedExact,
}

/// Parses draft-ietf-oauth-attestation-based-client-auth-07 challenge output.
///
/// The draft permits additional JSON members, but requires HTTP 200,
/// `application/json`, `Cache-Control: no-store`, and an
/// `attestation_challenge` string for attestation deployments.
pub fn parse_attestation_challenge_response(
    status: u16,
    content_type: &str,
    cache_control_values: &[&str],
    body: &[u8],
) -> OauthResult<AttestationChallenge> {
    if status != HTTP_STATUS_OK
        || !is_json_media_type(content_type)
        || !has_no_store(cache_control_values)
        || body.len() > MAX_JSON_BYTES
    {
        return Err(OauthError::new(Reason::InvalidAttestationChallengeResponse));
    }
    validate_strict_json(body)
        .map_err(|_| OauthError::new(Reason::InvalidAttestationChallengeResponse))?;
    let mut value: Value = serde_json::from_slice(body)
        .map_err(|_| OauthError::new(Reason::InvalidAttestationChallengeResponse))?;
    let challenge = value
        .as_object()
        .and_then(|object| object.get(ATTESTATION_CHALLENGE_MEMBER))
        .and_then(Value::as_str)
        .map(|challenge| Zeroizing::new(challenge.to_owned()))
        .ok_or_else(|| OauthError::new(Reason::InvalidAttestationChallengeResponse));
    zeroize_json_value(&mut value);
    let challenge = challenge?;
    validate_token(&challenge)
        .map_err(|_| OauthError::new(Reason::InvalidAttestationChallengeResponse))?;
    Ok(AttestationChallenge { value: challenge })
}

/// Parses a fresh `OAuth-Client-Attestation-Challenge` response header.
///
/// Exactly one field value is required so combined or duplicated security
/// headers cannot be interpreted differently by adjacent HTTP layers.
pub fn parse_attestation_challenge_header(values: &[&str]) -> OauthResult<AttestationChallenge> {
    let [challenge] = values else {
        return Err(OauthError::new(Reason::InvalidAttestationChallengeResponse));
    };
    validate_token(challenge)
        .map_err(|_| OauthError::new(Reason::InvalidAttestationChallengeResponse))?;
    Ok(AttestationChallenge {
        value: Zeroizing::new((*challenge).to_owned()),
    })
}

/// Classifies RFC 9449 nonce responses and permits at most one retry.
///
/// `error` is the parsed OAuth error for Authorization Server responses or the
/// parsed DPoP `WWW-Authenticate` error parameter for Resource Server
/// responses. HTTP syntax parsing remains the adapter's responsibility.
pub fn evaluate_dpop_nonce_response<'a>(
    endpoint: DpopNonceEndpoint,
    status: u16,
    error: Option<&str>,
    dpop_nonce_values: &'a [&'a str],
    retry_already_attempted: bool,
) -> OauthResult<DpopNonceDecision<'a>> {
    if dpop_nonce_values.len() > 1 {
        return Err(OauthError::new(Reason::InvalidDpopNonceResponse));
    }
    let nonce = dpop_nonce_values.first().copied();
    if let Some(value) = nonce {
        validate_dpop_nonce(value)?;
    }

    let challenge = match endpoint {
        DpopNonceEndpoint::AuthorizationServer => {
            status == HTTP_STATUS_BAD_REQUEST && error == Some(USE_DPOP_NONCE)
        }
        DpopNonceEndpoint::ResourceServer => {
            status == HTTP_STATUS_UNAUTHORIZED && error == Some(USE_DPOP_NONCE)
        }
    };
    if challenge && nonce.is_none() {
        return Err(OauthError::new(Reason::InvalidDpopNonceResponse));
    }
    if challenge && retry_already_attempted {
        return Err(OauthError::new(Reason::DpopNonceRetryExhausted));
    }

    Ok(DpopNonceDecision {
        nonce,
        retry: challenge,
    })
}

/// Applies RFC 9207 issuer-parameter validation using simple string comparison.
pub fn validate_authorization_response_issuer(
    expected_issuer: &str,
    metadata_advertises_issuer: bool,
    response_issuer_values: &[&str],
    policy: AuthorizationResponseIssuerPolicy,
) -> OauthResult<()> {
    validate_issuer_identifier(expected_issuer)?;
    if response_issuer_values.len() > 1 {
        return Err(OauthError::new(Reason::AuthorizationServerIssuerMismatch));
    }
    let received = response_issuer_values.first().copied();
    if let Some(value) = received {
        validate_issuer_identifier(value)
            .map_err(|_| OauthError::new(Reason::AuthorizationServerIssuerMismatch))?;
        if value != expected_issuer {
            return Err(OauthError::new(Reason::AuthorizationServerIssuerMismatch));
        }
    }

    if metadata_advertises_issuer || policy == AuthorizationResponseIssuerPolicy::RequireExact {
        return received.map_or_else(
            || Err(OauthError::new(Reason::AuthorizationResponseIssuerRequired)),
            |_| Ok(()),
        );
    }
    if received.is_some() && policy == AuthorizationResponseIssuerPolicy::MetadataDrivenStrict {
        return Err(OauthError::new(
            Reason::AuthorizationResponseIssuerUnexpected,
        ));
    }
    Ok(())
}

fn is_json_media_type(content_type: &str) -> bool {
    content_type
        .split(';')
        .next()
        .is_some_and(|media_type| media_type.trim().eq_ignore_ascii_case(APPLICATION_JSON))
}

fn has_no_store(values: &[&str]) -> bool {
    values.iter().any(|value| {
        value
            .split(',')
            .any(|directive| directive.trim().eq_ignore_ascii_case("no-store"))
    })
}

fn validate_dpop_nonce(value: &str) -> OauthResult<()> {
    if value.is_empty()
        || value.len() > crate::validation::MAX_TOKEN_BYTES
        || value
            .bytes()
            .any(|byte| !matches!(byte, 0x21 | 0x23..=0x5b | 0x5d..=0x7e))
    {
        return Err(OauthError::new(Reason::InvalidDpopNonceResponse));
    }
    Ok(())
}
