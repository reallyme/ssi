// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::collections::BTreeSet;
use std::fmt::Formatter;

use reallyme_codec::{
    base64::{base64_to_bytes, bytes_to_base64},
    base64url::base64url_to_bytes,
};
use reallyme_crypto::jwk::{p256_public_key_to_jwk, Jwk, JwkOptions};
use reallyme_jose::jwt::{
    decode_verify_jwt_signature_only_with_header_validation, JwtHeaderValidationOptions,
    MAX_COMPACT_JWT_BYTES,
};
use serde::de::{IgnoredAny, MapAccess, Visitor};
use serde::Deserialize;
use zeroize::Zeroizing;

use super::check_freshness::check_freshness;
use super::issue_jwt::validate_claims;
use super::model::{
    TokenStatusListClaims, TokenStatusListError, TokenStatusListFreshnessPolicy,
    VerifiedTokenStatusList, MAX_TOKEN_STATUS_X5C_CERTIFICATES,
    MAX_TOKEN_STATUS_X5C_CERTIFICATE_BYTES, MAX_TOKEN_STATUS_X5C_CHAIN_BYTES, STATUS_LIST_JWT_TYPE,
};

const ACCEPTED_TYPES: &[&str] = &[STATUS_LIST_JWT_TYPE];
const MAX_X5C_PROTECTED_HEADER_BYTES: usize = 524_288;
const MAX_X5C_PROTECTED_HEADER_ENCODED_BYTES: usize = 699_052;
const MAX_X5C_CERTIFICATE_ENCODED_BYTES: usize = 87_384;

#[derive(Default)]
struct X5cProtectedHeader {
    algorithm: Option<String>,
    token_type: Option<String>,
    certificate_chain: Option<Vec<String>>,
}

impl<'de> Deserialize<'de> for X5cProtectedHeader {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_map(X5cProtectedHeaderVisitor)
    }
}

struct X5cProtectedHeaderVisitor;

impl<'de> Visitor<'de> for X5cProtectedHeaderVisitor {
    type Value = X5cProtectedHeader;

    fn expecting(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a bounded Token Status List x5c protected header")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut header = X5cProtectedHeader::default();
        let mut seen = BTreeSet::new();

        while let Some(key) = map.next_key::<String>()? {
            if !seen.insert(key.clone()) {
                return Err(serde::de::Error::custom(
                    "duplicate protected header member",
                ));
            }
            match key.as_str() {
                "alg" => header.algorithm = Some(map.next_value()?),
                "typ" => header.token_type = Some(map.next_value()?),
                "x5c" => header.certificate_chain = Some(map.next_value()?),
                // This profile deliberately excludes every alternative key
                // selector and JOSE extension. Trust may originate only in the
                // exact certificate path authenticated by the resolver below.
                _ => {
                    let _ = map.next_value::<IgnoredAny>()?;
                    return Err(serde::de::Error::custom(
                        "unsupported protected header member",
                    ));
                }
            }
        }

        Ok(header)
    }
}

/// Verify, validate, and decompress a compact Token Status List JWT.
///
/// `freshness` bounds how long after `iat` the list is accepted, honoring a
/// shorter `ttl` claim; see [`TokenStatusListFreshnessPolicy`].
pub fn verify_token_status_list_jwt(
    jwt: &str,
    issuer_jwk: &Jwk,
    issuer_public_key: &[u8],
    expected_status_list_uri: &str,
    now_unix: u64,
    freshness: TokenStatusListFreshnessPolicy,
) -> Result<VerifiedTokenStatusList, TokenStatusListError> {
    let claims: TokenStatusListClaims = decode_verify_jwt_signature_only_with_header_validation(
        jwt,
        issuer_jwk,
        issuer_public_key,
        &JwtHeaderValidationOptions::new(false, false, ACCEPTED_TYPES),
    )
    .map_err(|_| TokenStatusListError::Authentication)?;
    finish_verification(claims, expected_status_list_uri, now_unix, freshness)
}

/// Verify a compact Token Status List JWT through its protected `x5c` path.
///
/// The resolver receives the exact decoded DER chain in leaf-first order and
/// the caller's verification time. It must perform complete X.509 path,
/// profile, purpose, and time validation against deployment-controlled trust
/// anchors. Returning `None` rejects the path; returning bytes asserts that
/// they are the authenticated leaf certificate's P-256 SEC1 public key.
///
/// The presented chain is never treated as a trust source. This function
/// accepts only `alg`, `typ`, and `x5c` protected members, canonicalizes the
/// resolver's key through a validated P-256 JWK, and then binds that key to the
/// JWS signature before applying the ordinary subject and freshness checks.
pub fn verify_token_status_list_jwt_with_x5c(
    jwt: &str,
    certificate_path_resolver: impl FnOnce(&[Vec<u8>], u64) -> Option<Vec<u8>>,
    expected_status_list_uri: &str,
    now_unix: u64,
    freshness: TokenStatusListFreshnessPolicy,
) -> Result<VerifiedTokenStatusList, TokenStatusListError> {
    let certificate_chain = parse_x5c_protected_header(jwt)?;
    let leaf_public_key = Zeroizing::new(
        certificate_path_resolver(&certificate_chain, now_unix)
            .ok_or(TokenStatusListError::CertificatePathRejected)?,
    );
    let issuer_jwk = Jwk::Ec(
        p256_public_key_to_jwk(
            &leaf_public_key,
            JwkOptions {
                alg: true,
                use_sig: true,
                use_enc: false,
                kid: None,
            },
        )
        .map_err(|_| TokenStatusListError::InvalidCertificateKey)?,
    );
    // Re-derive the bytes from the JWK. This validates the curve point and
    // gives JOSE one canonical compressed encoding for key/header binding.
    let canonical_public_key = Zeroizing::new(
        issuer_jwk
            .public_key_bytes()
            .map_err(|_| TokenStatusListError::InvalidCertificateKey)?,
    );
    let claims: TokenStatusListClaims = decode_verify_jwt_signature_only_with_header_validation(
        jwt,
        &issuer_jwk,
        &canonical_public_key,
        &JwtHeaderValidationOptions::new(false, true, ACCEPTED_TYPES),
    )
    .map_err(|_| TokenStatusListError::Authentication)?;
    finish_verification(claims, expected_status_list_uri, now_unix, freshness)
}

fn parse_x5c_protected_header(jwt: &str) -> Result<Vec<Vec<u8>>, TokenStatusListError> {
    if jwt.is_empty() || jwt.len() > MAX_COMPACT_JWT_BYTES {
        return Err(TokenStatusListError::InvalidCertificateChain);
    }
    let mut components = jwt.split('.');
    let protected = components
        .next()
        .ok_or(TokenStatusListError::InvalidCertificateChain)?;
    let payload = components
        .next()
        .ok_or(TokenStatusListError::InvalidCertificateChain)?;
    let signature = components
        .next()
        .ok_or(TokenStatusListError::InvalidCertificateChain)?;
    if protected.is_empty()
        || payload.is_empty()
        || signature.is_empty()
        || protected.len() > MAX_X5C_PROTECTED_HEADER_ENCODED_BYTES
        || components.next().is_some()
    {
        return Err(TokenStatusListError::InvalidCertificateChain);
    }
    let protected =
        base64url_to_bytes(protected).map_err(|_| TokenStatusListError::InvalidCertificateChain)?;
    if protected.is_empty() || protected.len() > MAX_X5C_PROTECTED_HEADER_BYTES {
        return Err(TokenStatusListError::InvalidCertificateChain);
    }
    let header: X5cProtectedHeader = serde_json::from_slice(&protected)
        .map_err(|_| TokenStatusListError::InvalidCertificateChain)?;
    if header.algorithm.as_deref() != Some("ES256")
        || header.token_type.as_deref() != Some(STATUS_LIST_JWT_TYPE)
    {
        return Err(TokenStatusListError::InvalidCertificateChain);
    }
    let encoded_chain = header
        .certificate_chain
        .ok_or(TokenStatusListError::InvalidCertificateChain)?;
    if encoded_chain.is_empty() || encoded_chain.len() > MAX_TOKEN_STATUS_X5C_CERTIFICATES {
        return Err(TokenStatusListError::InvalidCertificateChain);
    }

    let mut aggregate_length = 0_usize;
    let mut chain = Vec::with_capacity(encoded_chain.len());
    for encoded_certificate in encoded_chain {
        if encoded_certificate.is_empty()
            || encoded_certificate.len() > MAX_X5C_CERTIFICATE_ENCODED_BYTES
        {
            return Err(TokenStatusListError::InvalidCertificateChain);
        }
        let certificate = base64_to_bytes(&encoded_certificate)
            .map_err(|_| TokenStatusListError::InvalidCertificateChain)?;
        if certificate.is_empty()
            || certificate.len() > MAX_TOKEN_STATUS_X5C_CERTIFICATE_BYTES
            || bytes_to_base64(&certificate) != encoded_certificate
        {
            return Err(TokenStatusListError::InvalidCertificateChain);
        }
        aggregate_length = aggregate_length
            .checked_add(certificate.len())
            .ok_or(TokenStatusListError::InvalidCertificateChain)?;
        if aggregate_length > MAX_TOKEN_STATUS_X5C_CHAIN_BYTES {
            return Err(TokenStatusListError::InvalidCertificateChain);
        }
        chain.push(certificate);
    }
    Ok(chain)
}

fn finish_verification(
    claims: TokenStatusListClaims,
    expected_status_list_uri: &str,
    now_unix: u64,
    freshness: TokenStatusListFreshnessPolicy,
) -> Result<VerifiedTokenStatusList, TokenStatusListError> {
    let decoded = validate_claims(&claims)?;
    if claims.sub != expected_status_list_uri {
        return Err(TokenStatusListError::SubjectMismatch);
    }
    check_freshness(&claims, now_unix, freshness)?;
    Ok(VerifiedTokenStatusList {
        claims,
        packed_statuses: decoded.packed,
    })
}
