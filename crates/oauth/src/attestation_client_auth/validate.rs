// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Validation of attestation-based client authentication envelopes.

use reallyme_crypto::operations::constant_time::equal as constant_time_equal;
use reallyme_crypto::sha2::digest as digest_sha2_256;
use serde::Deserialize;
use serde_json::Value;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use super::{
    AttestationClientAuthentication, AttestationClientAuthenticationValidationContext,
    AttestationClientAuthenticationVerifier, AttestationPopClaims, AttestationPopHeader,
    VerifiedAttestationClientAuthentication, VerifiedClientAttestation,
    MAX_ATTESTATION_FUTURE_IAT_SKEW_SECONDS, SHA_256_BYTES,
};
use crate::error::{OauthError, OauthResult, Reason};
use crate::jwt::{decode_compact_jwt, CompactJwt};
use crate::validation::{validate_asymmetric_jose_alg, validate_issuer_identifier, validate_token};

/// Validates complete attestation-based client authentication headers.
pub fn validate_attestation_client_authentication(
    authentication: &AttestationClientAuthentication,
    context: &AttestationClientAuthenticationValidationContext,
    verifier: &dyn AttestationClientAuthenticationVerifier,
) -> OauthResult<VerifiedAttestationClientAuthentication> {
    authentication.validate()?;
    context.validate()?;
    let client_attestation = CompactJwt::new(authentication.client_attestation.clone())?;
    let pop = CompactJwt::new(authentication.client_attestation_pop.clone())?;
    validate_client_attestation_envelope(&client_attestation, context.current_time)?;
    let trust_evidence = verifier.verify_client_attestation(&client_attestation)?;
    let mut verified_attestation =
        VerifiedClientAttestation::bind(&client_attestation, trust_evidence)?;
    if !constant_time_equal(
        verified_attestation
            .attested_client_key()
            .client_id()
            .as_bytes(),
        context.expected_client_id.as_bytes(),
    ) {
        return Err(OauthError::new(Reason::AttestationClientIdMismatch));
    }
    verified_attestation.validate_trust_evidence_freshness(
        context.current_time,
        context.max_trust_evidence_age_seconds,
    )?;
    let decoded_pop = decode_and_validate_attestation_pop(
        &pop,
        &context.expected_audience,
        context.expected_challenge.as_deref(),
        context.earliest_iat,
        context.latest_iat,
    )?;
    if !verified_attestation
        .attested_client_key()
        .permits_algorithm(&decoded_pop.algorithm)
    {
        return Err(OauthError::new(Reason::AttestationKeyBindingFailed));
    }
    verifier
        .verify_pop_signature(
            &verified_attestation,
            &decoded_pop.header_value,
            decoded_pop.signing_input.as_bytes(),
            &decoded_pop.signature,
        )
        .map_err(|_| OauthError::new(Reason::AttestationKeyBindingFailed))?;
    verifier
        .check_replay(
            &verified_attestation,
            &decoded_pop.claims.jti,
            decoded_pop.claims.iat,
        )
        .map_err(|_| OauthError::new(Reason::AttestationReplay))?;
    let pop_jti_sha256 = sha256(decoded_pop.claims.jti.as_bytes());
    Ok(VerifiedAttestationClientAuthentication::new(
        decoded_pop.claims,
        verified_attestation,
        pop_jti_sha256,
    ))
}

#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
struct ClientAttestationHeader {
    typ: String,
    alg: String,
    kid: Option<String>,
}

#[derive(Deserialize)]
struct ClientAttestationTemporalClaims {
    exp: i64,
    iat: i64,
}

fn validate_client_attestation_envelope(
    client_attestation: &CompactJwt,
    current_time: i64,
) -> OauthResult<()> {
    let (header, claims, _signature): (
        ClientAttestationHeader,
        ClientAttestationTemporalClaims,
        Vec<u8>,
    ) = decode_compact_jwt(client_attestation)
        .map_err(|_| OauthError::new(Reason::InvalidClientAttestation))?;
    let latest_permitted_iat = current_time
        .checked_add(MAX_ATTESTATION_FUTURE_IAT_SKEW_SECONDS)
        .ok_or_else(|| OauthError::new(Reason::InvalidClientAttestation))?;
    if header.typ != "oauth-client-attestation+jwt"
        || claims.exp <= current_time
        || claims.iat <= 0
        || claims.iat > latest_permitted_iat
        || header
            .kid
            .as_deref()
            .is_some_and(|key_id| validate_token(key_id).is_err())
    {
        return Err(OauthError::new(Reason::InvalidClientAttestation));
    }
    validate_asymmetric_jose_alg(&header.alg)
        .map_err(|_| OauthError::new(Reason::InvalidClientAttestation))
}

fn sha256(value: &[u8]) -> [u8; SHA_256_BYTES] {
    *digest_sha2_256(value).as_bytes()
}

struct DecodedAttestationPop {
    header_value: Value,
    algorithm: String,
    claims: AttestationPopClaims,
    signing_input: Zeroizing<String>,
    signature: Vec<u8>,
}

fn decode_and_validate_attestation_pop(
    jwt: &CompactJwt,
    expected_audience: &str,
    expected_challenge: Option<&str>,
    earliest_iat: i64,
    latest_iat: i64,
) -> OauthResult<DecodedAttestationPop> {
    validate_issuer_identifier(expected_audience)?;
    let (header, claims, signature): (AttestationPopHeader, AttestationPopClaims, Vec<u8>) =
        decode_compact_jwt(jwt)?;
    if header.typ != "oauth-client-attestation-pop+jwt" {
        return Err(OauthError::new(Reason::InvalidClientAttestation));
    }
    validate_asymmetric_jose_alg(&header.alg)
        .map_err(|_| OauthError::new(Reason::InvalidClientAttestation))?;
    claims.validate()?;
    if claims.aud != expected_audience {
        return Err(OauthError::new(Reason::InvalidClientAttestation));
    }
    if let Some(challenge) = expected_challenge {
        if claims
            .challenge
            .as_deref()
            .is_none_or(|received| !constant_time_equal(received.as_bytes(), challenge.as_bytes()))
        {
            return Err(OauthError::new(Reason::InvalidClientAttestation));
        }
    }
    if claims.iat < earliest_iat || claims.iat > latest_iat {
        return Err(OauthError::new(Reason::InvalidClientAttestation));
    }
    let algorithm = header.alg.clone();
    let header_value =
        serde_json::to_value(&header).map_err(|_| OauthError::new(Reason::InvalidJson))?;
    let (signing_input, _) = jwt.signing_parts()?;
    Ok(DecodedAttestationPop {
        header_value,
        algorithm,
        claims,
        signing_input: Zeroizing::new(signing_input.to_owned()),
        signature,
    })
}
