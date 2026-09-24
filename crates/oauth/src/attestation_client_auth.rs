// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Attestation-based client authentication draft support.

use core::fmt;

use reallyme_crypto::sha2::digest as digest_sha2_256;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::error::{OauthError, OauthResult, Reason};
use crate::jwt::{decode_compact_jwt, sign_compact_jwt, CompactJwt, JwtSigner};
use crate::sensitive::zeroize_option;
use crate::validation::{
    validate_asymmetric_jose_alg, validate_compact_jwt, validate_issuer_identifier, validate_token,
};

pub use crate::attestation_trust_receipt::{
    VerifiedAttestationClientAuthentication, VerifiedClientAttestation,
    WalletAttestationTrustEvidence,
};
pub use crate::bind_attested_client_key::AttestedClientKey;

pub(crate) const SHA_256_BYTES: usize = 32;

/// Maximum age accepted for an already-computed wallet-attestation trust
/// decision. This bounds reuse of status and trust-list evidence independently
/// of the signer's certificate expiry.
pub const MAX_ATTESTATION_TRUST_EVIDENCE_AGE_SECONDS: i64 = 300;

/// HTTP header carrying the Client Attestation JWT.
pub const OAUTH_CLIENT_ATTESTATION_HEADER: &str = "OAuth-Client-Attestation";

/// HTTP header carrying the Client Attestation PoP JWT.
pub const OAUTH_CLIENT_ATTESTATION_POP_HEADER: &str = "OAuth-Client-Attestation-PoP";

/// Wallet attestation client authentication header values.
#[derive(PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestationClientAuthentication {
    /// Client Attestation JWT.
    pub client_attestation: String,
    /// Client Attestation PoP JWT.
    pub client_attestation_pop: String,
}

impl fmt::Debug for AttestationClientAuthentication {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AttestationClientAuthentication([REDACTED])")
    }
}

impl Zeroize for AttestationClientAuthentication {
    fn zeroize(&mut self) {
        self.client_attestation.zeroize();
        self.client_attestation_pop.zeroize();
    }
}

impl Drop for AttestationClientAuthentication {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for AttestationClientAuthentication {}

impl AttestationClientAuthentication {
    /// Creates client authentication values after compact JWT validation.
    pub fn new(client_attestation: String, client_attestation_pop: String) -> OauthResult<Self> {
        let value = Self {
            client_attestation,
            client_attestation_pop,
        };
        value.validate()?;
        Ok(value)
    }

    /// Validates compact JWT shape.
    pub fn validate(&self) -> OauthResult<()> {
        validate_compact_jwt(&self.client_attestation)?;
        validate_compact_jwt(&self.client_attestation_pop)
    }

    /// Returns HTTP header pairs for adapters.
    pub fn headers(&self) -> OauthResult<[(&'static str, &str); 2]> {
        self.validate()?;
        Ok([
            (
                OAUTH_CLIENT_ATTESTATION_HEADER,
                self.client_attestation.as_str(),
            ),
            (
                OAUTH_CLIENT_ATTESTATION_POP_HEADER,
                self.client_attestation_pop.as_str(),
            ),
        ])
    }
}

/// Client Attestation PoP JWT header.
#[derive(PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttestationPopHeader {
    /// JOSE type.
    pub typ: String,
    /// JOSE algorithm.
    pub alg: String,
}

impl fmt::Debug for AttestationPopHeader {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AttestationPopHeader([REDACTED])")
    }
}

impl Zeroize for AttestationPopHeader {
    fn zeroize(&mut self) {
        self.typ.zeroize();
        self.alg.zeroize();
    }
}

impl Drop for AttestationPopHeader {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for AttestationPopHeader {}

/// Client Attestation PoP JWT claims.
#[derive(PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestationPopClaims {
    /// OAuth client identifier bound to the Client Attestation `sub` claim.
    pub iss: String,
    /// Audience, normally the RFC 8414 Authorization Server issuer identifier.
    pub aud: String,
    /// Unique replay-prevention identifier.
    pub jti: String,
    /// Issued-at Unix timestamp.
    pub iat: i64,
    /// Optional server-provided challenge.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub challenge: Option<String>,
}

impl fmt::Debug for AttestationPopClaims {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AttestationPopClaims([REDACTED])")
    }
}

impl Zeroize for AttestationPopClaims {
    fn zeroize(&mut self) {
        self.iss.zeroize();
        self.aud.zeroize();
        self.jti.zeroize();
        zeroize_option(&mut self.challenge);
    }
}

impl Drop for AttestationPopClaims {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for AttestationPopClaims {}

impl AttestationPopClaims {
    /// Validates the PoP claim set.
    pub fn validate(&self) -> OauthResult<()> {
        validate_token(&self.iss)?;
        validate_issuer_identifier(&self.aud)?;
        validate_token(&self.jti)?;
        if self.iat <= 0 {
            return Err(OauthError::new(Reason::InvalidClientAttestation));
        }
        if let Some(challenge) = &self.challenge {
            validate_token(challenge)?;
        }
        Ok(())
    }
}

/// Issuer-side validation context for attestation-based client authentication.
#[derive(PartialEq, Eq)]
pub struct AttestationClientAuthenticationValidationContext {
    /// Expected Authorization Server audience.
    pub expected_audience: String,
    /// Optional issuer challenge that must appear in the PoP JWT.
    pub expected_challenge: Option<String>,
    /// Earliest accepted issued-at timestamp.
    pub earliest_iat: i64,
    /// Latest accepted issued-at timestamp.
    pub latest_iat: i64,
    /// Trusted request-processing time used to validate the trust receipt.
    pub current_time: i64,
    /// Maximum age of the wallet-attestation trust decision.
    pub max_trust_evidence_age_seconds: i64,
}

impl fmt::Debug for AttestationClientAuthenticationValidationContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AttestationClientAuthenticationValidationContext([REDACTED])")
    }
}

impl Zeroize for AttestationClientAuthenticationValidationContext {
    fn zeroize(&mut self) {
        self.expected_audience.zeroize();
        zeroize_option(&mut self.expected_challenge);
    }
}

impl Drop for AttestationClientAuthenticationValidationContext {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for AttestationClientAuthenticationValidationContext {}

impl AttestationClientAuthenticationValidationContext {
    /// Validates the context before it is used for client authentication.
    pub fn validate(&self) -> OauthResult<()> {
        validate_issuer_identifier(&self.expected_audience)?;
        if let Some(challenge) = &self.expected_challenge {
            validate_token(challenge)?;
        }
        if self.earliest_iat <= 0
            || self.latest_iat < self.earliest_iat
            || self.current_time < self.earliest_iat
            || self.current_time > self.latest_iat
            || self.max_trust_evidence_age_seconds <= 0
            || self.max_trust_evidence_age_seconds > MAX_ATTESTATION_TRUST_EVIDENCE_AGE_SECONDS
        {
            return Err(OauthError::new(Reason::InvalidClientAttestation));
        }
        Ok(())
    }
}

/// Verifier injected by issuer adapters for wallet attestation client auth.
pub trait AttestationClientAuthenticationVerifier {
    /// Verifies the wallet Client Attestation JWT signature and signer trust.
    fn verify_client_attestation(
        &self,
        client_attestation: &CompactJwt,
    ) -> OauthResult<WalletAttestationTrustEvidence>;

    /// Verifies the PoP JWT signature using only `attested_client_key`.
    ///
    /// The key is extracted by this crate from the `cnf.jwk` member of the
    /// exact attestation accepted by `verify_client_attestation`; adapters must
    /// not select a separate key from ambient request or session state.
    fn verify_pop_signature(
        &self,
        verified_attestation: &VerifiedClientAttestation,
        protected_header: &Value,
        signing_input: &[u8],
        signature: &[u8],
    ) -> OauthResult<()>;

    /// Enforces PoP replay protection for the validated `jti`.
    fn check_replay(
        &self,
        verified_attestation: &VerifiedClientAttestation,
        jti: &str,
        iat: i64,
    ) -> OauthResult<()>;
}

/// Holder-side Client Attestation PoP build request.
#[derive(PartialEq, Eq)]
pub struct AttestationPopRequest {
    /// OAuth client identifier also carried by the attestation `sub` claim.
    pub issuer: String,
    /// Authorization Server audience.
    pub audience: String,
    /// Unique PoP identifier.
    pub jti: String,
    /// Issued-at Unix timestamp.
    pub iat: i64,
    /// Optional challenge.
    pub challenge: Option<String>,
}

impl fmt::Debug for AttestationPopRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AttestationPopRequest([REDACTED])")
    }
}

impl Zeroize for AttestationPopRequest {
    fn zeroize(&mut self) {
        self.issuer.zeroize();
        self.audience.zeroize();
        self.jti.zeroize();
        zeroize_option(&mut self.challenge);
    }
}

impl Drop for AttestationPopRequest {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for AttestationPopRequest {}

impl AttestationPopRequest {
    /// Signs the Client Attestation PoP JWT.
    pub fn sign(&self, signer: &dyn JwtSigner) -> OauthResult<CompactJwt> {
        let header = AttestationPopHeader {
            typ: "oauth-client-attestation-pop+jwt".to_owned(),
            alg: signer.algorithm().to_owned(),
        };
        validate_asymmetric_jose_alg(&header.alg)
            .map_err(|_| OauthError::new(Reason::InvalidClientAttestation))?;
        let claims = AttestationPopClaims {
            iss: self.issuer.clone(),
            aud: self.audience.clone(),
            jti: self.jti.clone(),
            iat: self.iat,
            challenge: self.challenge.clone(),
        };
        claims.validate()?;
        sign_compact_jwt(&header, &claims, signer)
    }
}

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
    if *verified_attestation.client_attestation_sha256()
        != sha256(client_attestation.as_str().as_bytes())
    {
        return Err(OauthError::new(Reason::InvalidAttestationReceipt));
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
    if decoded_pop.claims.iss != verified_attestation.attested_client_key().client_id() {
        return Err(OauthError::new(Reason::AttestationKeyBindingFailed));
    }
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

#[derive(Deserialize)]
struct ClientAttestationHeader {
    typ: String,
    alg: String,
}

#[derive(Deserialize)]
struct ClientAttestationTemporalClaims {
    exp: i64,
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
    if header.typ != "oauth-client-attestation+jwt" || claims.exp <= current_time {
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
        if claims.challenge.as_deref() != Some(challenge) {
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
