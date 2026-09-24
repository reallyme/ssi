// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! RFC 9449 DPoP proof generation and validation.

use core::fmt;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::bind_attested_client_key::validate_public_signature_jwk;
use crate::error::{OauthError, OauthResult, Reason};
use crate::jwt::{decode_compact_jwt, sign_compact_jwt, CompactJwt, JwtSigner};
use crate::sensitive::{zeroize_json_value, zeroize_option};
use crate::validation::{
    normalize_uri_without_query_or_fragment, validate_asymmetric_jose_alg, validate_token,
};
use reallyme_codec::base64url::bytes_to_base64url;
use reallyme_crypto::operations::constant_time::equal as constant_time_equal;
use reallyme_crypto::sha2::digest as digest_sha2_256;

const MAX_JWK_THUMBPRINT_MEMBER_BYTES: usize = 8_192;

/// DPoP proof header.
#[derive(PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DpopHeader {
    /// JOSE type.
    pub typ: String,
    /// JOSE signing algorithm.
    pub alg: String,
    /// Public JWK for the proof key.
    pub jwk: Value,
}

impl fmt::Debug for DpopHeader {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DpopHeader([REDACTED])")
    }
}

impl Zeroize for DpopHeader {
    fn zeroize(&mut self) {
        self.typ.zeroize();
        self.alg.zeroize();
        zeroize_json_value(&mut self.jwk);
    }
}

impl Drop for DpopHeader {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for DpopHeader {}

impl DpopHeader {
    /// Creates a DPoP header.
    pub fn new(alg: String, jwk: Value) -> OauthResult<Self> {
        validate_token(&alg)?;
        validate_dpop_public_jwk(&alg, &jwk)?;
        Ok(Self {
            typ: "dpop+jwt".to_owned(),
            alg,
            jwk,
        })
    }

    /// Validates the DPoP header.
    pub fn validate(&self) -> OauthResult<()> {
        if self.typ != "dpop+jwt" {
            return Err(OauthError::new(Reason::InvalidDpopProof));
        }
        validate_token(&self.alg)?;
        validate_dpop_public_jwk(&self.alg, &self.jwk)
    }
}

/// Enforces that a DPoP proof key is an asymmetric public JWK and that the
/// `alg` is a registered asymmetric signature algorithm (RFC 9449 §4.2/§4.3).
fn validate_dpop_public_jwk(alg: &str, jwk: &Value) -> OauthResult<()> {
    validate_asymmetric_jose_alg(alg).map_err(|_| OauthError::new(Reason::InvalidDpopProof))?;
    // RFC 9449 §4.2 requires an asymmetric public JWK and prohibits private
    // key material. Applying the same closed member and key-family rules as
    // attestation PoP also prevents an injected verifier from selecting x5c,
    // x5u, or jku material that the RFC 7638 proof-key identity did not bind.
    validate_public_signature_jwk(jwk, Some(alg), Reason::InvalidDpopProof)
}

/// DPoP proof claims.
#[derive(PartialEq, Eq, Serialize, Deserialize)]
pub struct DpopClaims {
    /// Unique proof identifier.
    pub jti: String,
    /// HTTP method.
    pub htm: String,
    /// HTTP target URI without query or fragment.
    pub htu: String,
    /// Issued-at Unix timestamp.
    pub iat: i64,
    /// Access-token hash.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ath: Option<String>,
    /// DPoP nonce.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
}

impl fmt::Debug for DpopClaims {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DpopClaims([REDACTED])")
    }
}

impl Zeroize for DpopClaims {
    fn zeroize(&mut self) {
        self.jti.zeroize();
        self.htm.zeroize();
        self.htu.zeroize();
        zeroize_option(&mut self.ath);
        zeroize_option(&mut self.nonce);
    }
}

impl Drop for DpopClaims {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for DpopClaims {}

impl DpopClaims {
    /// Validates DPoP claim shape.
    pub fn validate(&self) -> OauthResult<()> {
        validate_token(&self.jti)?;
        validate_token(&self.htm)?;
        validate_token(&self.htu)?;
        if self.iat <= 0 {
            return Err(OauthError::new(Reason::InvalidDpopProof));
        }
        if let Some(ath) = &self.ath {
            validate_token(ath)?;
        }
        if let Some(nonce) = &self.nonce {
            validate_token(nonce)?;
        }
        Ok(())
    }
}

/// Inputs used by a holder to create a DPoP proof.
#[derive(PartialEq)]
pub struct DpopProofRequest {
    /// HTTP method.
    pub method: String,
    /// Full target URI. Query and fragment are removed for `htu`.
    pub target_uri: String,
    /// Unique proof identifier.
    pub jti: String,
    /// Issued-at Unix timestamp.
    pub iat: i64,
    /// Public JWK.
    pub public_jwk: Value,
    /// Optional access token for `ath`.
    pub access_token: Option<String>,
    /// Optional nonce.
    pub nonce: Option<String>,
}

impl fmt::Debug for DpopProofRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DpopProofRequest([REDACTED])")
    }
}

impl Zeroize for DpopProofRequest {
    fn zeroize(&mut self) {
        self.method.zeroize();
        self.target_uri.zeroize();
        self.jti.zeroize();
        zeroize_json_value(&mut self.public_jwk);
        zeroize_option(&mut self.access_token);
        zeroize_option(&mut self.nonce);
    }
}

impl Drop for DpopProofRequest {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for DpopProofRequest {}

impl DpopProofRequest {
    /// Creates a signed DPoP proof JWT.
    pub fn sign(&self, signer: &dyn JwtSigner) -> OauthResult<DpopProof> {
        validate_token(&self.method)?;
        validate_token(&self.jti)?;
        let header = DpopHeader::new(signer.algorithm().to_owned(), self.public_jwk.clone())?;
        let claims = DpopClaims {
            jti: self.jti.clone(),
            htm: self.method.to_uppercase(),
            htu: normalize_uri_without_query_or_fragment(&self.target_uri)?,
            iat: self.iat,
            ath: self
                .access_token
                .as_ref()
                .map(|token| hash_ascii(token.as_bytes())),
            nonce: self.nonce.clone(),
        };
        claims.validate()?;
        let jwt = sign_compact_jwt(&header, &claims, signer)?;
        Ok(DpopProof { jwt })
    }
}

/// Compact DPoP proof JWT.
#[derive(PartialEq, Eq)]
pub struct DpopProof {
    jwt: CompactJwt,
}

impl fmt::Debug for DpopProof {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DpopProof([REDACTED])")
    }
}

impl DpopProof {
    /// Creates a proof from a compact JWT.
    pub fn new(jwt: String) -> OauthResult<Self> {
        Ok(Self {
            jwt: CompactJwt::new(jwt)?,
        })
    }

    /// Returns the compact JWT value.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.jwt.as_str()
    }

    /// Decodes and validates with an injected verifier.
    pub fn validate(
        &self,
        context: &DpopValidationContext,
        verifier: &dyn DpopVerifier,
    ) -> OauthResult<()> {
        let (header, claims, signature): (DpopHeader, DpopClaims, Vec<u8>) =
            decode_compact_jwt(&self.jwt)?;
        header.validate()?;
        claims.validate()?;
        if claims.htm != context.method.to_uppercase() {
            return Err(OauthError::new(Reason::InvalidDpopProof));
        }
        let expected_htu = normalize_uri_without_query_or_fragment(&context.target_uri)?;
        let observed_htu = normalize_uri_without_query_or_fragment(&claims.htu)?;
        if observed_htu != expected_htu {
            return Err(OauthError::new(Reason::InvalidDpopProof));
        }
        if let Some(expected_nonce) = &context.nonce {
            if claims.nonce.as_ref().is_none_or(|nonce| {
                !constant_time_equal(nonce.as_bytes(), expected_nonce.as_bytes())
            }) {
                return Err(OauthError::new(Reason::InvalidDpopProof));
            }
        }
        if let Some(access_token) = &context.access_token {
            let expected_ath = hash_ascii(access_token.as_bytes());
            if claims
                .ath
                .as_deref()
                .is_none_or(|ath| !constant_time_equal(ath.as_bytes(), expected_ath.as_bytes()))
            {
                return Err(OauthError::new(Reason::InvalidDpopProof));
            }
        }
        if claims.iat < context.earliest_iat || claims.iat > context.latest_iat {
            return Err(OauthError::new(Reason::InvalidDpopProof));
        }
        // RFC 9449 §4.3(12): confirm the DPoP proof key is the key the access
        // token is bound to, by comparing the RFC 7638 JWK thumbprint of the
        // proof header key against the token's confirmed `cnf.jkt`.
        if let Some(confirmed_jkt) = &context.confirmed_jkt {
            let proof_jkt = jwk_thumbprint(&header.jwk)?;
            if !constant_time_equal(proof_jkt.as_bytes(), confirmed_jkt.as_bytes()) {
                return Err(OauthError::new(Reason::InvalidDpopProof));
            }
        }
        let header_value =
            serde_json::to_value(&header).map_err(|_| OauthError::new(Reason::InvalidJson))?;
        let (signing_input, _) = self.jwt.signing_parts()?;
        verifier.verify_signature(&header_value, signing_input.as_bytes(), &signature)?;
        verifier.check_replay(&claims.jti, claims.iat)?;
        Ok(())
    }

    /// Returns the RFC 7638 thumbprint of the public JWK carried in the proof
    /// header after validating the header shape.
    pub fn public_jwk_thumbprint(&self) -> OauthResult<String> {
        let (header, _claims, _signature): (DpopHeader, DpopClaims, Vec<u8>) =
            decode_compact_jwt(&self.jwt)?;
        header.validate()?;
        jwk_thumbprint(&header.jwk)
    }
}

/// DPoP validation context supplied by issuer adapters.
#[derive(PartialEq, Eq)]
pub struct DpopValidationContext {
    /// HTTP method.
    pub method: String,
    /// Target URI.
    pub target_uri: String,
    /// Optional access token that must match `ath`.
    pub access_token: Option<String>,
    /// Optional server nonce.
    pub nonce: Option<String>,
    /// Earliest accepted issued-at timestamp.
    pub earliest_iat: i64,
    /// Latest accepted issued-at timestamp.
    pub latest_iat: i64,
    /// Access token's confirmed `cnf.jkt` thumbprint. When present, the DPoP
    /// proof key must match it (RFC 9449 sender-constraint). Adapters that treat
    /// the access token as opaque leave this `None`.
    pub confirmed_jkt: Option<String>,
}

impl fmt::Debug for DpopValidationContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DpopValidationContext([REDACTED])")
    }
}

impl Zeroize for DpopValidationContext {
    fn zeroize(&mut self) {
        self.method.zeroize();
        self.target_uri.zeroize();
        zeroize_option(&mut self.access_token);
        zeroize_option(&mut self.nonce);
        zeroize_option(&mut self.confirmed_jkt);
    }
}

impl Drop for DpopValidationContext {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for DpopValidationContext {}

/// Computes the RFC 7638 JWK SHA-256 thumbprint (base64url, no padding) used as
/// the DPoP `jkt` confirmation value.
pub fn jwk_thumbprint(jwk: &Value) -> OauthResult<String> {
    let object = jwk
        .as_object()
        .ok_or(OauthError::new(Reason::InvalidDpopProof))?;
    let kty = object
        .get("kty")
        .and_then(Value::as_str)
        .ok_or(OauthError::new(Reason::InvalidDpopProof))?;
    // RFC 7638 §3.2: the required members, in lexicographic order, with no
    // whitespace, per key type.
    let required: &[&str] = match kty {
        "EC" => &["crv", "kty", "x", "y"],
        "OKP" => &["crv", "kty", "x"],
        "RSA" => &["e", "kty", "n"],
        "oct" => &["k", "kty"],
        _ => return Err(OauthError::new(Reason::InvalidDpopProof)),
    };
    let mut canonical = Zeroizing::new(String::from("{"));
    for (index, member) in required.iter().enumerate() {
        let value = object
            .get(*member)
            .and_then(Value::as_str)
            .ok_or(OauthError::new(Reason::InvalidDpopProof))?;
        if value.is_empty() || value.len() > MAX_JWK_THUMBPRINT_MEMBER_BYTES {
            return Err(OauthError::new(Reason::InvalidDpopProof));
        }
        if index > 0 {
            canonical.push(',');
        }
        write_json_string(&mut canonical, member)?;
        canonical.push(':');
        write_json_string(&mut canonical, value)?;
    }
    canonical.push('}');
    Ok(bytes_to_base64url(
        digest_sha2_256(canonical.as_bytes()).as_bytes(),
    ))
}

/// Appends one complete RFC 8259 JSON string representation.
///
/// RFC 7638 §3.2 requires the thumbprint input to be a valid JSON object.
/// Delegating all mandatory control-character escaping to the JSON serializer
/// avoids producing a non-JSON canonical form for adversarial direct callers.
fn write_json_string(out: &mut String, value: &str) -> OauthResult<()> {
    let encoded = Zeroizing::new(
        serde_json::to_string(value).map_err(|_| OauthError::new(Reason::InvalidDpopProof))?,
    );
    out.push_str(&encoded);
    Ok(())
}

/// DPoP verifier with signature and replay hooks.
pub trait DpopVerifier {
    /// Verifies the proof signature.
    fn verify_signature(
        &self,
        protected_header: &Value,
        signing_input: &[u8],
        signature: &[u8],
    ) -> OauthResult<()>;

    /// Enforces replay protection for a `jti` and issued-at timestamp.
    fn check_replay(&self, jti: &str, iat: i64) -> OauthResult<()>;
}

fn hash_ascii(value: &[u8]) -> String {
    bytes_to_base64url(digest_sha2_256(value).as_bytes())
}
