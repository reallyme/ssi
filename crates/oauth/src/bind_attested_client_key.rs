// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Bind Client Attestation verification to its Client Instance Key.

use core::fmt;

use reallyme_codec::base64url::base64url_to_bytes;
use serde::Deserialize;
use serde_json::Value;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::dpop::jwk_thumbprint;
use crate::error::{OauthError, OauthResult, Reason};
use crate::jwt::{decode_compact_jwt, CompactJwt};
use crate::sensitive::zeroize_json_value;
use crate::validation::{validate_asymmetric_jose_alg, validate_token};

const COMMON_PUBLIC_JWK_MEMBERS: &[&str] = &["kty", "use", "key_ops", "alg", "kid"];

#[derive(Deserialize)]
struct ClientAttestationBindingClaims {
    sub: String,
    cnf: ClientAttestationConfirmation,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ClientAttestationConfirmation {
    jwk: Value,
}

/// Client Instance Key extracted from a cryptographically verified attestation.
///
/// This type cannot be constructed by adapters. The complete authentication
/// validator creates it from the `cnf.jwk` member of the exact Client
/// Attestation JWT passed to the attestation verifier, then supplies it to PoP
/// verification. This capability boundary prevents an adapter from
/// accidentally selecting an unrelated ambient PoP key.
#[derive(PartialEq, Eq)]
pub struct AttestedClientKey {
    client_id: String,
    public_jwk: Value,
    thumbprint: String,
    thumbprint_sha256: [u8; 32],
}

impl fmt::Debug for AttestedClientKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AttestedClientKey([REDACTED])")
    }
}

impl Zeroize for AttestedClientKey {
    fn zeroize(&mut self) {
        self.client_id.zeroize();
        zeroize_json_value(&mut self.public_jwk);
        self.thumbprint.zeroize();
        self.thumbprint_sha256.zeroize();
    }
}

impl Drop for AttestedClientKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for AttestedClientKey {}

impl AttestedClientKey {
    /// Returns the validated public JWK carried by the attestation `cnf` claim.
    #[must_use]
    pub fn public_jwk(&self) -> &Value {
        &self.public_jwk
    }

    /// Returns the RFC 7638 thumbprint of the attested Client Instance Key.
    #[must_use]
    pub fn thumbprint(&self) -> &str {
        &self.thumbprint
    }

    /// Raw RFC 7638 SHA-256 JWK thumbprint bytes.
    #[must_use]
    pub fn thumbprint_sha256(&self) -> &[u8; 32] {
        &self.thumbprint_sha256
    }

    /// OAuth client identifier authenticated by the attestation `sub` claim.
    #[must_use]
    pub(crate) fn client_id(&self) -> &str {
        self.client_id.as_str()
    }

    /// Whether this key's family, curve, and optional declared `alg` permit a
    /// PoP protected-header algorithm.
    ///
    /// RFC 7517 §4.4 makes `alg` a key-use restriction. Checking it here, in
    /// addition to cryptographic verification, prevents algorithm/key-family
    /// confusion in injected JOSE adapters.
    #[must_use]
    pub fn permits_algorithm(&self, algorithm: &str) -> bool {
        public_jwk_permits_algorithm(&self.public_jwk, algorithm)
    }

    pub(crate) fn from_client_attestation(client_attestation: &CompactJwt) -> OauthResult<Self> {
        let (_header, claims, _signature): (Value, ClientAttestationBindingClaims, Vec<u8>) =
            decode_compact_jwt(client_attestation)
                .map_err(|_| OauthError::new(Reason::InvalidClientAttestation))?;
        validate_token(&claims.sub)
            .map_err(|_| OauthError::new(Reason::InvalidClientAttestation))?;
        let public_jwk = claims.cnf.jwk;
        let thumbprint = validate_attested_public_jwk(&public_jwk)?;
        let mut decoded_thumbprint = base64url_to_bytes(&thumbprint)
            .map_err(|_| OauthError::new(Reason::InvalidClientAttestation))?;
        let thumbprint_result = <[u8; 32]>::try_from(decoded_thumbprint.as_slice());
        decoded_thumbprint.zeroize();
        let thumbprint_sha256 =
            thumbprint_result.map_err(|_| OauthError::new(Reason::InvalidClientAttestation))?;
        Ok(Self {
            client_id: claims.sub,
            public_jwk,
            thumbprint,
            thumbprint_sha256,
        })
    }
}

fn validate_attested_public_jwk(jwk: &Value) -> OauthResult<String> {
    validate_public_signature_jwk(jwk, None, Reason::InvalidClientAttestation)?;
    jwk_thumbprint(jwk).map_err(|_| OauthError::new(Reason::InvalidClientAttestation))
}

pub(crate) fn validate_public_signature_jwk(
    jwk: &Value,
    expected_algorithm: Option<&str>,
    failure: Reason,
) -> OauthResult<()> {
    let object = jwk.as_object().ok_or(OauthError::new(failure))?;
    let key_specific_members: &[&str] = match object.get("kty").and_then(Value::as_str) {
        Some("EC") => &["crv", "x", "y"],
        Some("OKP") => &["crv", "x"],
        Some("RSA") => &["n", "e"],
        _ => return Err(OauthError::new(failure)),
    };
    // RFC 7638 hashes only the required public members. Reject every other
    // key-specific or indirection member (including private parameters, `k`,
    // `x5c`, `x5u`, and `jku`) so an adapter cannot verify with material that
    // the attestation's thumbprint did not bind.
    if object.keys().any(|member| {
        !COMMON_PUBLIC_JWK_MEMBERS.contains(&member.as_str())
            && !key_specific_members.contains(&member.as_str())
    }) || key_specific_members.iter().any(|member| {
        object
            .get(*member)
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
    }) {
        return Err(OauthError::new(failure));
    }
    if let Some(usage) = object.get("use") {
        if usage.as_str() != Some("sig") {
            return Err(OauthError::new(failure));
        }
    }
    if let Some(operations) = object.get("key_ops") {
        let operations = operations.as_array().ok_or(OauthError::new(failure))?;
        if operations.len() != 1 || operations.first().and_then(Value::as_str) != Some("verify") {
            return Err(OauthError::new(failure));
        }
    }
    if let Some(algorithm) = object.get("alg") {
        let algorithm = algorithm.as_str().ok_or(OauthError::new(failure))?;
        validate_asymmetric_jose_alg(algorithm).map_err(|_| OauthError::new(failure))?;
        if expected_algorithm.is_some_and(|expected| expected != algorithm) {
            return Err(OauthError::new(failure));
        }
    }
    if expected_algorithm.is_some_and(|algorithm| !public_jwk_permits_algorithm(jwk, algorithm)) {
        return Err(OauthError::new(failure));
    }
    Ok(())
}

fn public_jwk_permits_algorithm(jwk: &Value, algorithm: &str) -> bool {
    let Some(object) = jwk.as_object() else {
        return false;
    };
    if object
        .get("alg")
        .is_some_and(|declared| declared.as_str() != Some(algorithm))
    {
        return false;
    }
    matches!(
        (
            object.get("kty").and_then(Value::as_str),
            object.get("crv").and_then(Value::as_str),
            algorithm,
        ),
        (Some("EC"), Some("P-256"), "ES256")
            | (Some("EC"), Some("P-384"), "ES384")
            | (Some("EC"), Some("P-521"), "ES512")
            | (Some("EC"), Some("secp256k1"), "ES256K")
            | (Some("OKP"), Some("Ed25519" | "Ed448"), "EdDSA")
            | (
                Some("RSA"),
                _,
                "PS256" | "PS384" | "PS512" | "RS256" | "RS384" | "RS512"
            )
    )
}
