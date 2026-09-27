// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use codec_base64url::bytes_to_base64url;
use envelopes_jwk::Jwk;
use envelopes_jwt::jwt::{encode_signed_jwt_with_header_options, JwtHeaderEncodeOptions};

use identity_presentation_vp_core::model::SdJwtVcPresentation;
use reallyme_credential::committed::model::SubjectPrivateBundle;
use reallyme_crypto::sha2::digest as sha2_256_digest;
use zeroize::Zeroizing;

use crate::error::SdJwtVpError;

/// Transaction-binding inputs for the legacy ReallyMe Merkle envelope.
///
/// These values are carried in the key binding JWT payload so verifiers can validate
/// request/response binding (nonce, audience, and issue time).
#[derive(Debug, Clone)]
pub struct KbJwtBindingInput<'a> {
    /// OpenID4VP nonce (string as received in the authorization request).
    pub nonce: &'a str,
    /// Expected audience (typically the normalized OpenID4VP client_id).
    pub aud: &'a str,
    /// JWT issued-at (unix seconds).
    pub iat_unix: u64,
}

/// Build an SD-JWT VC presentation using an issuer-signed SD-JWT.
///
/// This function:
/// - DOES NOT create or sign the SD-JWT
/// - ONLY selects disclosures from the subject bundle
///
/// Inputs:
/// - `bundle`: holder’s SubjectPrivateBundle
/// - `issuer_sd_jwt`: issuer-signed SD-JWT VC (compact JWS)
/// - `disclose_paths`: claim paths to disclose
pub fn build_sd_jwt_presentation(
    bundle: &SubjectPrivateBundle,
    issuer_sd_jwt: String,
    disclose_paths: &[String],
) -> Result<SdJwtVcPresentation, SdJwtVpError> {
    let envelope_hash: [u8; 32] = bundle
        .envelope_hash
        .clone()
        .try_into()
        .map_err(|_| SdJwtVpError::InvalidBundle)?;

    let mut disclosures = Vec::new();

    for path in disclose_paths {
        let opening = bundle
            .claims
            .iter()
            .find(|c| &c.claim_path == path)
            .ok_or(SdJwtVpError::ClaimNotFound)?;

        let disclosure_json = serde_json::json!([
            bytes_to_base64url(&opening.salt),
            opening.claim_path,
            bytes_to_base64url(&opening.value),
            opening.index,
            opening
                .merkle_path
                .iter()
                .map(|h| bytes_to_base64url(h))
                .collect::<Vec<_>>(),
        ]);

        let disclosure_bytes =
            serde_json::to_vec(&disclosure_json).map_err(|_| SdJwtVpError::Serialization)?;

        disclosures.push(bytes_to_base64url(&disclosure_bytes));
    }

    Ok(SdJwtVcPresentation {
        sd_jwt: issuer_sd_jwt,
        disclosures,
        kb_jwt: None,
        vct: None,
        envelope_hash: Some(envelope_hash),
    })
}

/// Build a legacy ReallyMe Merkle-envelope presentation with a key-binding JWT.
///
/// This does not compute the RFC 9901 serialized-presentation `sd_hash` and is
/// therefore not the builder used by the OpenID4VP conformance path.
/// The compatibility payload carries these transaction-binding claims:
/// - `nonce`
/// - `aud`
/// - `iat`
pub fn build_sd_jwt_presentation_with_kb_binding(
    bundle: &SubjectPrivateBundle,
    issuer_sd_jwt: String,
    disclose_paths: &[String],
    holder_jwk: &Jwk,
    holder_private_key: &[u8],
    binding: KbJwtBindingInput<'_>,
) -> Result<SdJwtVcPresentation, SdJwtVpError> {
    if binding.aud.is_empty() || binding.nonce.is_empty() || binding.iat_unix == 0 {
        return Err(SdJwtVpError::Crypto);
    }
    let envelope_hash: [u8; 32] = bundle
        .envelope_hash
        .clone()
        .try_into()
        .map_err(|_| SdJwtVpError::InvalidBundle)?;

    let mut pres = build_sd_jwt_presentation(bundle, issuer_sd_jwt, disclose_paths)?;
    let disclosure_set_hash = canonical_disclosure_set_hash(&pres.disclosures)?;
    let payload = serde_json::json!({
        "sd_hash": bytes_to_base64url(envelope_hash.as_ref()),
        "disclosure_set_hash": bytes_to_base64url(disclosure_set_hash.as_bytes()),
        "aud": binding.aud,
        "nonce": binding.nonce,
        "iat": binding.iat_unix,
    });

    let kb_jwt = encode_signed_jwt_with_header_options(
        &payload,
        holder_jwk,
        holder_private_key,
        &JwtHeaderEncodeOptions::new(Some("kb+jwt".to_owned())),
    )
    .map_err(|_| SdJwtVpError::Crypto)?;

    pres.kb_jwt = Some(kb_jwt);
    Ok(pres)
}

pub(crate) fn canonical_disclosure_set_hash(
    disclosures: &[String],
) -> Result<reallyme_crypto::sha2::Sha2_256Digest, SdJwtVpError> {
    let mut ordered = disclosures.iter().map(String::as_str).collect::<Vec<_>>();
    ordered.sort_unstable();
    if ordered
        .windows(2)
        .any(|pair| matches!(pair, [left, right] if left == right))
    {
        return Err(SdJwtVpError::DisclosureSetMismatch);
    }
    let encoded =
        Zeroizing::new(serde_json::to_vec(&ordered).map_err(|_| SdJwtVpError::Serialization)?);
    Ok(sha2_256_digest(&encoded))
}

#[cfg(test)]
#[path = "build/protocol_wire_vector_tests.rs"]
mod protocol_wire_vector_tests;
