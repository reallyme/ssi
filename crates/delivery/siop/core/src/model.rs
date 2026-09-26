// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// SIOP v2 Authentication Request (minimal, transport-neutral).
///
/// Aligned with proto `SiopAuthenticationRequest`.
#[derive(PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct SiopAuthenticationRequest {
    /// Relying party client identifier.
    pub client_id: String,

    /// Challenge / nonce (bytes, typically 32).
    pub nonce: Vec<u8>,

    /// Audience string (RP-defined).
    pub audience: String,

    /// Requested response mode (e.g. "direct_post").
    pub response_mode: String,

    /// Requested scopes (e.g. ["openid"]).
    pub scope: Vec<String>,

    /// Unix seconds.
    pub created_at: u64,

    /// Unix seconds.
    pub expires_at: u64,
}

/// SIOP v2 Authentication Response (minimal, transport-neutral).
///
/// Aligned with proto `SiopAuthenticationResponse`.
#[derive(PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct SiopAuthenticationResponse {
    /// Self-issued ID token (JWT bytes).
    pub id_token: Vec<u8>,

    /// Optional state binding.
    pub state: Option<String>,
}

/// Minimal typed JWT claims for SIOP id_token verification.
///
/// Only fields enforced by verifier logic are modeled.
#[derive(Serialize, Deserialize, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct SiopIdTokenClaims {
    /// Issuer identifier from the SIOP ID token.
    pub iss: String,

    /// Subject identifier from the SIOP ID token.
    pub sub: String,

    /// Audience values accepted by the ID token verifier.
    #[serde(deserialize_with = "aud_deserialize", serialize_with = "aud_serialize")]
    pub aud: Vec<String>,

    /// Nonce value that must match the originating request.
    pub nonce: String,

    /// Issued-at timestamp in Unix seconds.
    pub iat: i64,

    /// Expiration timestamp in Unix seconds.
    pub exp: i64,

    /// Public JWK of the self-issued subject (SIOPv2 `sub_jwk`).
    ///
    /// Required when `sub` uses the JWK thumbprint subject syntax type and
    /// rejected for DID subjects.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sub_jwk: Option<SiopSubjectJwk>,
}

/// Public JWK members relevant to RFC 7638 thumbprint computation.
///
/// Only asymmetric `EC` and `OKP` signature keys are modeled; other members
/// such as `alg`, `use`, or `kid` are ignored because they do not participate
/// in the thumbprint.
#[derive(Serialize, Deserialize, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct SiopSubjectJwk {
    /// JWK key type (`EC` or `OKP`).
    pub kty: String,

    /// JWK curve name.
    pub crv: String,

    /// Base64url x coordinate or OKP public key.
    pub x: String,

    /// Base64url y coordinate for `EC` keys.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub y: Option<String>,
}

// Requests, responses, and verified claims contain stable identifiers, bearer
// tokens, and replay-binding material. A uniform policy prevents newly added
// fields from becoming visible through diagnostics by default.
macro_rules! impl_redacted_debug {
    ($($type_name:ty),+ $(,)?) => {
        $(
            impl core::fmt::Debug for $type_name {
                fn fmt(
                    &self,
                    formatter: &mut core::fmt::Formatter<'_>,
                ) -> core::fmt::Result {
                    formatter
                        .debug_struct(stringify!($type_name))
                        .field("contents", &"<redacted>")
                        .finish()
                }
            }
        )+
    };
}

impl_redacted_debug!(
    SiopAuthenticationRequest,
    SiopAuthenticationResponse,
    SiopIdTokenClaims,
    SiopSubjectJwk,
);

fn aud_deserialize<'de, D>(d: D) -> Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Aud {
        One(String),
        Many(Vec<String>),
    }

    match Aud::deserialize(d)? {
        Aud::One(s) => Ok(vec![s]),
        Aud::Many(v) => Ok(v),
    }
}

fn aud_serialize<S>(aud: &Vec<String>, s: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    if aud.len() == 1 {
        s.serialize_str(&aud[0])
    } else {
        aud.serialize(s)
    }
}
