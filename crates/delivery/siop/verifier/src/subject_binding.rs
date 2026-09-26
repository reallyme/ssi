// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! SIOPv2 self-issued subject binding.
//!
//! A self-issued ID token is only meaningful when its signature key is bound
//! to the asserted subject. SIOPv2 requires `iss == sub` and defines two
//! subject syntax types: a JWK thumbprint (`sub` is the base64url SHA-256
//! RFC 7638 thumbprint of `sub_jwk`) and a Decentralized Identifier (`sub` is
//! the DID and the signing key is a verification method of that DID).

use std::collections::BTreeMap;

use codec_base64url::bytes_to_base64url;
use envelopes_jwk::Jwk;
use identity_presentation_delivery_siop_core::{SiopIdTokenClaims, SiopSubjectJwk};
use reallyme_crypto::operations::constant_time::equal as constant_time_equal;
use reallyme_crypto::sha2::digest as sha2_256_digest;
use zeroize::Zeroizing;

use crate::SiopVerifierError;

/// URI scheme prefix identifying the DID subject syntax type.
const DID_SUBJECT_PREFIX: &str = "did:";

/// Separator between a DID and the verification-method fragment in `kid`.
const DID_URL_FRAGMENT_SEPARATOR: char = '#';

/// Base64url length of a SHA-256 JWK thumbprint without padding.
const JWK_THUMBPRINT_BASE64URL_BYTES: usize = 43;

/// Maximum accepted length of one JWK thumbprint member.
const MAX_JWK_MEMBER_BYTES: usize = 256;

const JWK_KTY_EC: &str = "EC";
const JWK_KTY_OKP: &str = "OKP";

/// Thumbprint-relevant public JWK members, borrowed from either JWK model.
struct ThumbprintMembers<'a> {
    kty: &'a str,
    crv: &'a str,
    x: &'a str,
    y: Option<&'a str>,
}

/// Require that the verified signing key is bound to the ID token subject.
pub(crate) fn verify_subject_binding(
    claims: &SiopIdTokenClaims,
    kid: Option<&str>,
    verifying_jwk: &Jwk,
) -> Result<(), SiopVerifierError> {
    if claims.iss != claims.sub {
        return Err(SiopVerifierError::SubjectMismatch);
    }

    if claims.sub.starts_with(DID_SUBJECT_PREFIX) {
        verify_did_subject(claims, kid)
    } else {
        verify_jwk_thumbprint_subject(claims, verifying_jwk)
    }
}

fn verify_did_subject(
    claims: &SiopIdTokenClaims,
    kid: Option<&str>,
) -> Result<(), SiopVerifierError> {
    if claims.sub_jwk.is_some() {
        return Err(SiopVerifierError::SubjectMismatch);
    }
    let kid = kid.ok_or(SiopVerifierError::SubjectMismatch)?;
    let (did, fragment) = kid
        .split_once(DID_URL_FRAGMENT_SEPARATOR)
        .ok_or(SiopVerifierError::SubjectMismatch)?;
    if fragment.is_empty() || did != claims.sub {
        return Err(SiopVerifierError::SubjectMismatch);
    }
    Ok(())
}

fn verify_jwk_thumbprint_subject(
    claims: &SiopIdTokenClaims,
    verifying_jwk: &Jwk,
) -> Result<(), SiopVerifierError> {
    if claims.sub.len() != JWK_THUMBPRINT_BASE64URL_BYTES {
        return Err(SiopVerifierError::SubjectMismatch);
    }
    let sub_jwk = claims
        .sub_jwk
        .as_ref()
        .ok_or(SiopVerifierError::SubjectMismatch)?;

    let claimed = jwk_thumbprint(&subject_jwk_members(sub_jwk))?;
    let verifying = jwk_thumbprint(&verifying_jwk_members(verifying_jwk)?)?;

    if !constant_time_equal(claimed.as_bytes(), claims.sub.as_bytes())
        || !constant_time_equal(verifying.as_bytes(), claims.sub.as_bytes())
    {
        return Err(SiopVerifierError::SubjectMismatch);
    }
    Ok(())
}

fn subject_jwk_members(jwk: &SiopSubjectJwk) -> ThumbprintMembers<'_> {
    ThumbprintMembers {
        kty: jwk.kty.as_str(),
        crv: jwk.crv.as_str(),
        x: jwk.x.as_str(),
        y: jwk.y.as_deref(),
    }
}

fn verifying_jwk_members(jwk: &Jwk) -> Result<ThumbprintMembers<'_>, SiopVerifierError> {
    match jwk {
        Jwk::Ec(ec) => Ok(ThumbprintMembers {
            kty: ec.kty.as_str(),
            crv: ec.crv.as_str(),
            x: ec.x.as_str(),
            y: Some(ec.y.as_str()),
        }),
        Jwk::Okp(okp) => Ok(ThumbprintMembers {
            kty: okp.kty.as_str(),
            crv: okp.crv.as_str(),
            x: okp.x.as_str(),
            y: None,
        }),
        _ => Err(SiopVerifierError::SubjectMismatch),
    }
}

/// Compute the RFC 7638 SHA-256 thumbprint as unpadded base64url.
fn jwk_thumbprint(members: &ThumbprintMembers<'_>) -> Result<String, SiopVerifierError> {
    let mut required = BTreeMap::new();
    required.insert("crv", members.crv);
    required.insert("kty", members.kty);
    required.insert("x", members.x);
    match (members.kty, members.y) {
        (JWK_KTY_EC, Some(y)) => {
            required.insert("y", y);
        }
        (JWK_KTY_OKP, None) => {}
        _ => return Err(SiopVerifierError::SubjectMismatch),
    }
    if required
        .values()
        .any(|value| value.is_empty() || value.len() > MAX_JWK_MEMBER_BYTES)
    {
        return Err(SiopVerifierError::SubjectMismatch);
    }

    // A BTreeMap serializes members in lexicographic order with no
    // insignificant whitespace, which is the RFC 7638 canonical form.
    let canonical =
        Zeroizing::new(serde_json::to_vec(&required).map_err(|_| SiopVerifierError::InvalidInput)?);
    let digest = sha2_256_digest(canonical.as_slice()).into_bytes();
    Ok(bytes_to_base64url(digest.as_slice()))
}

#[cfg(test)]
#[path = "subject_binding_tests.rs"]
mod tests;
