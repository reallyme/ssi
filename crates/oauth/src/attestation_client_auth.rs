// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Attestation-based client authentication draft support.

use core::fmt;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{OauthError, OauthResult, Reason};
use crate::jwt::{sign_compact_jwt, CompactJwt, JwtSigner};
use crate::sensitive::zeroize_option;
use crate::validation::{
    validate_asymmetric_jose_alg, validate_compact_jwt, validate_issuer_identifier, validate_token,
};

pub use crate::attestation_trust_receipt::{
    VerifiedAttestationClientAuthentication, VerifiedClientAttestation,
    WalletAttestationTrustEvidence,
};
pub use crate::bind_attested_client_key::AttestedClientKey;

mod validate;

pub use validate::validate_attestation_client_authentication;

pub(crate) const SHA_256_BYTES: usize = 32;

/// Maximum age accepted for an already-computed wallet-attestation trust
/// decision. This bounds reuse of status and trust-list evidence independently
/// of the signer's certificate expiry.
pub const MAX_ATTESTATION_TRUST_EVIDENCE_AGE_SECONDS: i64 = 300;
const MAX_ATTESTATION_FUTURE_IAT_SKEW_SECONDS: i64 = 60;

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
    /// OAuth request `client_id` that must equal the attestation `sub` claim.
    pub expected_client_id: String,
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
        self.expected_client_id.zeroize();
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
        validate_token(&self.expected_client_id)?;
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
        let latest_permitted_iat = self
            .current_time
            .checked_add(MAX_ATTESTATION_FUTURE_IAT_SKEW_SECONDS)
            .ok_or_else(|| OauthError::new(Reason::InvalidClientAttestation))?;
        if self.latest_iat > latest_permitted_iat {
            return Err(OauthError::new(Reason::InvalidClientAttestation));
        }
        Ok(())
    }
}

/// Verifier injected by issuer adapters for wallet attestation client auth.
pub trait AttestationClientAuthenticationVerifier {
    /// Verifies the wallet Client Attestation JWT signature and signer trust.
    ///
    /// Implementations must construct the returned receipt with the exact SPKI
    /// used for JWT signature verification. `WalletAttestationTrustEvidence`
    /// rejects a different leaf key from the selected trust path.
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
            aud: self.audience.clone(),
            jti: self.jti.clone(),
            iat: self.iat,
            challenge: self.challenge.clone(),
        };
        claims.validate()?;
        sign_compact_jwt(&header, &claims, signer)
    }
}
