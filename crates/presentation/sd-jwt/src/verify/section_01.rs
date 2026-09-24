// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use codec_base64url::base64url_to_bytes;
use envelopes_jwk::{
    ed25519_public_key_to_jwk, p256_public_key_to_jwk, secp256k1_public_key_to_jwk, Jwk, JwkOptions,
};
use envelopes_jwt::jwt::{
    decode_verify_jwt_signature_only, decode_verify_jwt_signature_only_with_header_validation,
    JwtHeaderValidationOptions, JwtTemporalValidationPolicy,
};

use reallyme_credential::committed::model::{
    CredentialEnvelope, HolderBinding, PublicKeyRepresentation,
};
use identity_presentation_vp_core::model::SdJwtVcPresentation;
use reallyme_crypto::sha2::digest as sha2_256_digest;

use crate::error::SdJwtVpError;

const MAX_TEMPORAL_SKEW_SECONDS: u64 = 300;
// Prevent a misconfigured verifier from turning KB-JWT freshness into an
// effectively unbounded bearer-token lifetime.
const MAX_KB_JWT_AGE_SECONDS: u64 = 86_400;

fn now_unix() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_secs(),
        Err(_) => 0,
    }
}

/// Expected binding constraints for the legacy ReallyMe Merkle envelope.
#[derive(Debug, Clone, Copy)]
pub struct ExpectedKbJwtBinding<'a> {
    /// Expected verifier audience for the KB-JWT.
    pub expected_audience: &'a str,
    /// Expected 32-byte nonce or challenge.
    pub expected_nonce_32: [u8; 32],
    /// Current verifier time as Unix seconds.
    pub now_unix: u64,
    /// Maximum age accepted for the KB-JWT `iat` claim.
    pub max_iat_age_seconds: u64,
    /// Maximum accepted future skew for the KB-JWT `iat` claim.
    pub max_future_iat_skew_seconds: u64,
}

/// Verified disclosure output (verifier-facing)
#[derive(Debug, Clone)]
pub struct VerifiedDisclosure {
    /// Canonical claim path disclosed by the holder.
    pub claim_path: String,
    /// JCS-encoded disclosed claim value.
    pub value_jcs: Vec<u8>,
}

/// Verify an SD-JWT VC presentation against a VC envelope.
///
/// This performs:
/// 1) Verify issuer SD-JWT VC signature (vp.sd_jwt)
/// 2) Binding check: sd_hash (base64url) must match vp.envelope_hash (if present)
/// 3) Verify the holder KB-JWT whenever the credential is cryptographically
///    holder-bound or an expected OpenID4VP binding is supplied
/// 4) Verify merkle proof for each disclosure against VC merkle_root
///
/// Inputs:
/// - `vp`: SD-JWT VP presentation (sd_jwt + disclosures + optional kb_jwt)
/// - `vc`: public VC envelope containing merkle_root + domain tags + limits
/// - `issuer_jwk`: issuer public JWK (must match issuer alg)
/// - `issuer_public_key`: issuer raw public key bytes (as required by crypto-dispatch backend)
/// - `holder_public_key`: optional holder public key bytes (required only if kb_jwt present)
pub fn verify_sd_jwt_vp(
    vp: &SdJwtVcPresentation,
    vc: &CredentialEnvelope,
    issuer_jwk: &Jwk,
    issuer_public_key: &[u8],
    holder_public_key: Option<&[u8]>,
) -> Result<Vec<VerifiedDisclosure>, SdJwtVpError> {
    if vp.kb_jwt.is_some() {
        return Err(SdJwtVpError::Crypto);
    }
    verify_sd_jwt_vp_inner(
        vp,
        vc,
        issuer_jwk,
        issuer_public_key,
        holder_public_key,
        None,
    )
}

/// Verify an SD-JWT VC presentation and require the exact OpenID4VP binding.
pub fn verify_sd_jwt_vp_with_binding(
    vp: &SdJwtVcPresentation,
    vc: &CredentialEnvelope,
    issuer_jwk: &Jwk,
    issuer_public_key: &[u8],
    holder_public_key: Option<&[u8]>,
    expected_binding: ExpectedKbJwtBinding<'_>,
) -> Result<Vec<VerifiedDisclosure>, SdJwtVpError> {
    verify_sd_jwt_vp_inner(
        vp,
        vc,
        issuer_jwk,
        issuer_public_key,
        holder_public_key,
        Some(expected_binding),
    )
}

fn verify_sd_jwt_vp_inner(
    vp: &SdJwtVcPresentation,
    vc: &CredentialEnvelope,
    issuer_jwk: &Jwk,
    issuer_public_key: &[u8],
    holder_public_key: Option<&[u8]>,
    expected_binding: Option<ExpectedKbJwtBinding<'_>>,
) -> Result<Vec<VerifiedDisclosure>, SdJwtVpError> {
    // --- 1) Verify issuer SD-JWT VC signature ---
    let payload: serde_json::Value =
        decode_verify_jwt_signature_only(&vp.sd_jwt, issuer_jwk, issuer_public_key)
            .map_err(|_| SdJwtVpError::Crypto)?;
    validate_temporal_claims(
        &payload,
        now_unix(),
        JwtTemporalValidationPolicy::new(true, true, false, 60, 60),
    )?;

    // --- 2) Binding check: sd_hash base64url(32) must match envelope_hash (if present) ---
    let sd_hash_b64 = payload
        .get("sd_hash")
        .and_then(|v| v.as_str())
        .ok_or(SdJwtVpError::InvalidDisclosure)?;

    let sd_hash = base64url_to_bytes(sd_hash_b64).map_err(|_| SdJwtVpError::InvalidDisclosure)?;

    if sd_hash.len() != 32 {
        return Err(SdJwtVpError::InvalidDisclosure);
    }

    if let Some(eh) = vp.envelope_hash {
        if sd_hash.as_slice() != eh {
            return Err(SdJwtVpError::InvalidDisclosure);
        }
    }

    // --- 3) Verify holder key binding JWT (kb_jwt) when binding is required ---
    if let Some(kb_jwt) = &vp.kb_jwt {
        let expected = expected_binding
            .as_ref()
            .ok_or(SdJwtVpError::MissingKeyBinding)?;
        let holder_pk = holder_public_key.ok_or(SdJwtVpError::Crypto)?;
        validate_envelope_holder_key(vc, holder_pk)?;

        let holder_jwk = jwk_for_public_key_for_jwt_alg(kb_jwt, holder_pk)?;

        let kb_payload: serde_json::Value =
            decode_verify_jwt_signature_only_with_header_validation(
                kb_jwt,
                &holder_jwk,
                holder_pk,
                &JwtHeaderValidationOptions::new(false, false, &["kb+jwt"]),
            )
            .map_err(|_| SdJwtVpError::Crypto)?;
        validate_temporal_claims(
            &kb_payload,
            expected.now_unix,
            JwtTemporalValidationPolicy::new(
                false,
                false,
                true,
                0,
                expected.max_future_iat_skew_seconds,
            ),
        )?;

        // Ensure KB-JWT binds to the same envelope hash used by issuer SD-JWT VC.
        let kb_sd_hash = kb_payload
            .get("sd_hash")
            .and_then(|v| v.as_str())
            .ok_or(SdJwtVpError::InvalidDisclosure)?;
        let kb_sd_hash_bytes =
            base64url_to_bytes(kb_sd_hash).map_err(|_| SdJwtVpError::InvalidDisclosure)?;
        if kb_sd_hash_bytes.len() != 32 || kb_sd_hash_bytes.as_slice() != sd_hash.as_slice() {
            return Err(SdJwtVpError::InvalidDisclosure);
        }

        validate_kb_jwt_claims(&kb_payload, expected)?;
    } else if expected_binding.is_some() {
        return Err(SdJwtVpError::MissingKeyBinding);
    }

    // --- 4) Verify each disclosure against VC merkle_root ---
    let out = verify_merkle_disclosures(vp, vc)?;

    // RFC 9901 §§3.3, 4.3, and 7.3 require an SD-JWT+KB whenever
    // application policy requires key binding. A cryptographic holder key in
    // the signed credential envelope is such a policy signal: accepting the
    // same presentation after an attacker strips its KB-JWT would turn the
    // credential into a replayable bearer token (CVE-2026-77456).
    if expected_binding.is_none()
        && matches!(
            &vc.subject.holder_binding,
            HolderBinding::CryptographicKey(_)
        )
    {
        return Err(SdJwtVpError::MissingKeyBinding);
    }

    Ok(out)
}

fn validate_envelope_holder_key(
    credential: &CredentialEnvelope,
    supplied_public_key: &[u8],
) -> Result<(), SdJwtVpError> {
    let envelope_public_key = match &credential.subject.holder_binding {
        HolderBinding::CryptographicKey(key) => match &key.public_key {
            PublicKeyRepresentation::Raw { bytes, .. } => bytes.as_slice(),
            _ => return Err(SdJwtVpError::Crypto),
        },
        HolderBinding::ClaimsBased(_) | HolderBinding::BearerWithoutBinding => {
            return Err(SdJwtVpError::MissingKeyBinding);
        }
    };

    // RFC 9901 §§4.1.2 and 7.3: a valid signature from an arbitrary key is
    // not holder binding. The KB-JWT verification key must be the key fixed by
    // the issuer-signed credential envelope.
    if envelope_public_key != supplied_public_key {
        return Err(SdJwtVpError::Crypto);
    }

    Ok(())
}

// -----------------------------------------------------------------------------
// Hash primitives (must match VC issue/verify)
// -----------------------------------------------------------------------------

fn jwk_for_public_key_for_jwt_alg(jwt: &str, public_key: &[u8]) -> Result<Jwk, SdJwtVpError> {
    // Decode header.alg without trusting the JWT (signature still verified by strict JWT verifier).
    let mut it = jwt.splitn(3, '.');
    let h = it.next().ok_or(SdJwtVpError::Crypto)?;
    let p = it.next().ok_or(SdJwtVpError::Crypto)?;
    let s = it.next().ok_or(SdJwtVpError::Crypto)?;
    if h.is_empty() || p.is_empty() || s.is_empty() {
        return Err(SdJwtVpError::Crypto);
    }
    let header_bytes = base64url_to_bytes(h).map_err(|_| SdJwtVpError::Crypto)?;

    let header: serde_json::Value =
        serde_json::from_slice(&header_bytes).map_err(|_| SdJwtVpError::Crypto)?;
    let alg = header
        .get("alg")
        .and_then(|v| v.as_str())
        .ok_or(SdJwtVpError::Crypto)?;

    // Build a matching JWK for algorithm/key-shape compatibility checks.
    let options = JwkOptions {
        alg: true,
        use_sig: true,
        use_enc: false,
        kid: header
            .get("kid")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
    };

    match alg {
        "EdDSA" => Ok(Jwk::Okp(
            ed25519_public_key_to_jwk(public_key, options)
                .map_err(|_| SdJwtVpError::Crypto)?
                .into(),
        )),
        "ES256" => Ok(Jwk::Ec(
            p256_public_key_to_jwk(public_key, options).map_err(|_| SdJwtVpError::Crypto)?,
        )),
        "ES256K" => Ok(Jwk::Ec(
            secp256k1_public_key_to_jwk(public_key, options).map_err(|_| SdJwtVpError::Crypto)?,
        )),
        _ => Err(SdJwtVpError::Crypto),
    }
}

fn sha256_32(data: &[u8]) -> [u8; 32] {
    sha2_256_digest(data).into_bytes()
}

fn nonce_str_to_32(nonce: &str) -> Result<[u8; 32], SdJwtVpError> {
    if let Ok(b) = base64url_to_bytes(nonce) {
        if b.len() == 32 {
            let arr: [u8; 32] = b.as_slice().try_into().map_err(|_| SdJwtVpError::Crypto)?;
            return Ok(arr);
        }
    }
    Ok(sha256_32(nonce.as_bytes()))
}

fn validate_kb_jwt_claims(
    payload: &serde_json::Value,
    expected: &ExpectedKbJwtBinding<'_>,
) -> Result<(), SdJwtVpError> {
    // aud (string or array)
    let aud = payload.get("aud").ok_or(SdJwtVpError::Crypto)?;
    let aud_ok = match aud {
        serde_json::Value::String(s) => s == expected.expected_audience,
        serde_json::Value::Array(arr) => arr
            .iter()
            .any(|v| v.as_str() == Some(expected.expected_audience)),
        _ => false,
    };
    if !aud_ok {
        return Err(SdJwtVpError::Crypto);
    }

    // nonce
    let nonce = payload
        .get("nonce")
        .and_then(|v| v.as_str())
        .ok_or(SdJwtVpError::Crypto)?;
    let nonce_32 = nonce_str_to_32(nonce)?;
    if nonce_32 != expected.expected_nonce_32 {
        return Err(SdJwtVpError::Crypto);
    }

    // This legacy envelope still requires an explicit, bounded `iat` window.
    // That closes replay of stale compatibility presentations and acceptance
    // of tokens issued unreasonably far in the future without claiming that
    // this non-RFC wire format is an RFC 9901 implementation.
    let iat = payload
        .get("iat")
        .and_then(|v| v.as_u64())
        .ok_or(SdJwtVpError::Crypto)?;
    if expected.max_iat_age_seconds == 0
        || expected.max_iat_age_seconds > MAX_KB_JWT_AGE_SECONDS
        || expected.max_future_iat_skew_seconds > MAX_TEMPORAL_SKEW_SECONDS
    {
        return Err(SdJwtVpError::Crypto);
    }
    let latest_iat = expected
        .now_unix
        .checked_add(expected.max_future_iat_skew_seconds)
        .ok_or(SdJwtVpError::Crypto)?;
    let stale_after = iat
        .checked_add(expected.max_iat_age_seconds)
        .ok_or(SdJwtVpError::Crypto)?;
    if iat > latest_iat || stale_after < expected.now_unix {
        return Err(SdJwtVpError::Crypto);
    }

    Ok(())
}

fn validate_temporal_claims(
    payload: &serde_json::Value,
    now_unix: u64,
    policy: JwtTemporalValidationPolicy,
) -> Result<(), SdJwtVpError> {
    if now_unix == 0
        || policy.clock_skew_seconds() > MAX_TEMPORAL_SKEW_SECONDS
        || policy.max_future_iat_skew_seconds() > MAX_TEMPORAL_SKEW_SECONDS
    {
        return Err(SdJwtVpError::Crypto);
    }

    let exp = parse_numeric_date(payload, "exp")?;
    let nbf = parse_numeric_date(payload, "nbf")?;
    let iat = parse_numeric_date(payload, "iat")?;

    if (policy.require_exp() && exp.is_none())
        || (policy.require_nbf() && nbf.is_none())
        || (policy.require_iat() && iat.is_none())
    {
        return Err(SdJwtVpError::Crypto);
    }

    validate_expiration(exp, now_unix, policy.clock_skew_seconds())?;
    validate_not_before(nbf, now_unix, policy.clock_skew_seconds())?;
    validate_issued_at(iat, now_unix, policy.max_future_iat_skew_seconds())
}

fn parse_numeric_date(
    payload: &serde_json::Value,
    claim_name: &str,
) -> Result<Option<u64>, SdJwtVpError> {
    let Some(value) = payload.get(claim_name) else {
        return Ok(None);
    };
    value.as_u64().map(Some).ok_or(SdJwtVpError::Crypto)
}

fn validate_expiration(
    exp: Option<u64>,
    now_unix: u64,
    clock_skew_seconds: u64,
) -> Result<(), SdJwtVpError> {
    let Some(exp_unix) = exp else {
        return Ok(());
    };
    if exp_unix == 0 {
        return Err(SdJwtVpError::Crypto);
    }
    let expiration_floor = skew_floor(now_unix, clock_skew_seconds)?;
    if expiration_floor >= exp_unix {
        return Err(SdJwtVpError::Crypto);
    }
    Ok(())
}
