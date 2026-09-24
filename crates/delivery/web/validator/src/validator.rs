// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Web / QR delivery-layer validation boundary.
//!
//! This module performs **cryptographic** VP/VC verification suitable for verifier-grade deployments:
//! - SD-JWT VC issuer signature verification
//! - SD-JWT disclosure/Merkle verification against the credential envelope
//! - SD-JWT KB-JWT holder binding signature (against envelope subject key)
//! - VP policy evaluation for SSI-owned presentation formats
//!
//! ZK proof selection and verification belong to the OpenID4VP format layer,
//! which composes SSI credential semantics with an injected ZK provider.

use identity_presentation_vp_validator::{
    validate_presentation, CryptoContext, QeaaContext, VpValidationError, VpValidationInput,
};

use identity_core_primitives::{vc_alg_str_to_alg, Algorithm};
use identity_credential_claims_core::ClaimsRegistry;
use identity_presentation_vp_core::model::{Presentation, SdJwtVcPresentation};
use identity_presentation_vp_policy::{PolicyDecision, StatusContext, VpPolicyError};
use identity_presentation_vp_sd_jwt::{
    verify_sd_jwt_vp, verify_sd_jwt_vp_with_binding, ExpectedKbJwtBinding,
};

use codec_base64url;
use reallyme_credential::committed::model::{
    CredentialEnvelope, HolderBinding, PublicKeyRepresentation,
};
use reallyme_crypto::sha2::digest as sha2_256_digest;
use serde::Deserialize;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const MAX_COMPACT_JWS_BYTES: usize = 16_384;
const MAX_PROTECTED_HEADER_BASE64URL_BYTES: usize = 2_048;
const MAX_JOSE_ALGORITHM_BYTES: usize = 32;

#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
struct ProtectedHeader {
    alg: String,
}

/// Result returned by the Web validator.
///
/// This is intentionally protocol-light and renderer-friendly.
#[derive(Debug)]
pub enum WebValidationResult {
    /// Presentation cryptography and policy checks passed.
    Accepted,
    /// Presentation was well-formed enough to evaluate but failed policy.
    Rejected(Vec<identity_presentation_vp_policy::VpPolicyError>),
}

/// Inputs required to validate a VP in a Web / QR / direct flow.
///
/// IMPORTANT:
/// - CryptoContext is NOT supplied
/// - It is derived from the presentation itself
pub struct WebValidationInput<'a> {
    /// Presentation received at the delivery boundary.
    pub presentation: &'a Presentation,
    /// Claim registry used to validate disclosed claim semantics.
    pub claims_registry: &'a ClaimsRegistry,
    /// Claimset identifier expected for this verification policy.
    pub claimset_id: &'a str,
    /// Optional status context supplied by the caller.
    pub status: Option<StatusContext<'a>>,
    /// Optional QEAA audit context supplied by the caller.
    pub qeaa: QeaaContext<'a>,

    /// Typed credential envelope for cryptographic verification of SD-JWT and ZK presentations.
    pub credential_envelope: Option<&'a CredentialEnvelope>,

    /// Issuer public key for SD-JWT VC signature verification (raw bytes).
    pub sd_jwt_issuer_public_key: Option<&'a [u8]>,

    /// Exact relying-party binding required for a holder-bound SD-JWT VC.
    ///
    /// Audience, nonce, trusted time, and maximum age are verified together
    /// with the holder signature; omitting this for a holder-bound credential
    /// fails closed.
    pub sd_jwt_binding: Option<ExpectedKbJwtBinding<'a>>,

    /// Current verifier time as Unix seconds.
    pub now_unix: u64,
}

/// Validate a VP received via a Web / QR / direct channel at the **delivery boundary**.
pub fn validate_web_presentation<'a>(
    input: WebValidationInput<'a>,
) -> Result<WebValidationResult, VpValidationError> {
    verify_presentation_crypto(&input)?;

    // ---------------------------------------------------------------------
    // 1) Derive cryptographic context from presentation
    // ---------------------------------------------------------------------
    let crypto = derive_crypto_context(input.presentation)?;

    // ---------------------------------------------------------------------
    // 2) Delegate VP policy verification
    // ---------------------------------------------------------------------
    let decision = validate_presentation(VpValidationInput {
        presentation: input.presentation,
        claims_registry: input.claims_registry,
        claimset_id: input.claimset_id,
        crypto,
        status: input.status,
        qeaa: input.qeaa,
        binding_ok: true, // trusted channel
        now_unix: input.now_unix,
    })?;

    Ok(match decision {
        PolicyDecision::Accept => WebValidationResult::Accepted,
        PolicyDecision::Reject(errs) => WebValidationResult::Rejected(errs),
    })
}

fn verify_presentation_crypto(input: &WebValidationInput<'_>) -> Result<(), VpValidationError> {
    match input.presentation {
        Presentation::SdJwtVc(sd) => {
            let env = input
                .credential_envelope
                .ok_or(VpValidationError::MissingCredentialEnvelope)?;

            if let Some(status) = input.status.as_ref() {
                enforce_status_binding_sd_jwt(env, status)?;
            }

            let issuer_pk = input
                .sd_jwt_issuer_public_key
                .ok_or_else(policy_misconfig)?;

            let issuer_algorithm = extract_jws_algorithm(&sd.sd_jwt)?;
            let issuer_jwk = jwk_for_algorithm_and_public_key(issuer_algorithm, issuer_pk)?;

            let holder_pk = match &env.subject.holder_binding {
                HolderBinding::CryptographicKey(key) => match &key.public_key {
                    PublicKeyRepresentation::Raw { bytes, .. } => Some(bytes.as_slice()),
                    _ => return Err(policy_misconfig()),
                },
                HolderBinding::ClaimsBased(_) | HolderBinding::BearerWithoutBinding => None,
            };

            let verification = match input.sd_jwt_binding {
                Some(binding) => verify_sd_jwt_vp_with_binding(
                    sd,
                    env,
                    &issuer_jwk,
                    issuer_pk,
                    holder_pk,
                    binding,
                ),
                None => verify_sd_jwt_vp(sd, env, &issuer_jwk, issuer_pk, holder_pk),
            };
            verification.map_err(|_| {
                VpValidationError::PolicyRejected(vec![VpPolicyError::ProofInvalid])
            })?;

            Ok(())
        }

        Presentation::Zk(_) => Err(VpValidationError::PolicyRejected(vec![
            VpPolicyError::PresentationFormatNotAllowed,
        ])),

        Presentation::Mdoc(_) => Err(VpValidationError::PolicyRejected(vec![
            VpPolicyError::PresentationFormatNotAllowed,
        ])),
    }
}

// -----------------------------------------------------------------------------
// Crypto derivation helpers (shared semantics with OpenID4VP)
// -----------------------------------------------------------------------------

fn derive_crypto_context(presentation: &Presentation) -> Result<CryptoContext, VpValidationError> {
    match presentation {
        Presentation::SdJwtVc(sd) => derive_sd_jwt_crypto(sd),
        Presentation::Zk(_) => Err(VpValidationError::PolicyRejected(vec![
            VpPolicyError::PresentationFormatNotAllowed,
        ])),
        Presentation::Mdoc(_) => Err(VpValidationError::PolicyRejected(vec![
            VpPolicyError::PresentationFormatNotAllowed,
        ])),
    }
}

fn derive_sd_jwt_crypto(sd: &SdJwtVcPresentation) -> Result<CryptoContext, VpValidationError> {
    let issuer_algorithm = extract_jws_algorithm(&sd.sd_jwt)?;

    let holder_algorithm = match sd.kb_jwt.as_deref() {
        Some(kb) => extract_jws_algorithm(kb)?,
        None => issuer_algorithm,
    };

    Ok(CryptoContext {
        issuer_algorithm,
        holder_algorithm,
    })
}

fn extract_jws_algorithm(jwt: &str) -> Result<Algorithm, VpValidationError> {
    if jwt.is_empty() || jwt.len() > MAX_COMPACT_JWS_BYTES {
        return Err(policy_misconfig());
    }

    let mut parts = jwt.split('.');
    let header_b64 = parts.next().ok_or_else(policy_misconfig)?;
    let payload_b64 = parts.next().ok_or_else(policy_misconfig)?;
    let signature_b64 = parts.next().ok_or_else(policy_misconfig)?;
    if header_b64.is_empty()
        || header_b64.len() > MAX_PROTECTED_HEADER_BASE64URL_BYTES
        || payload_b64.is_empty()
        || signature_b64.is_empty()
        || parts.next().is_some()
    {
        return Err(policy_misconfig());
    }

    let header_bytes = Zeroizing::new(
        codec_base64url::base64url_to_bytes(header_b64).map_err(|_| policy_misconfig())?,
    );

    let header: ProtectedHeader =
        serde_json::from_slice(&header_bytes).map_err(|_| policy_misconfig())?;
    if header.alg.is_empty() || header.alg.len() > MAX_JOSE_ALGORITHM_BYTES {
        return Err(policy_misconfig());
    }

    vc_alg_str_to_alg(&header.alg).map_err(|_| policy_misconfig())
}

fn policy_misconfig() -> VpValidationError {
    VpValidationError::PolicyRejected(vec![VpPolicyError::PolicyMisconfiguration])
}

fn jwk_for_algorithm_and_public_key(
    algorithm: Algorithm,
    public_key: &[u8],
) -> Result<envelopes_jwk::Jwk, VpValidationError> {
    let options = envelopes_jwk::JwkOptions {
        alg: true,
        use_sig: true,
        use_enc: false,
        kid: None,
    };

    match algorithm {
        Algorithm::Ed25519 => Ok(envelopes_jwk::Jwk::Okp(
            envelopes_jwk::ed25519_public_key_to_jwk(public_key, options)
                .map_err(|_| policy_misconfig())?
                .into(),
        )),
        Algorithm::P256 => Ok(envelopes_jwk::Jwk::Ec(
            envelopes_jwk::p256_public_key_to_jwk(public_key, options)
                .map_err(|_| policy_misconfig())?,
        )),
        Algorithm::Secp256k1 => Ok(envelopes_jwk::Jwk::Ec(
            envelopes_jwk::secp256k1_public_key_to_jwk(public_key, options)
                .map_err(|_| policy_misconfig())?,
        )),
        _ => Err(policy_misconfig()),
    }
}

fn sha256_32(bytes: &[u8]) -> [u8; 32] {
    sha2_256_digest(bytes).into_bytes()
}

fn purpose_matches_status_core(
    vc_purpose: reallyme_credential::committed::model::StatusPurpose,
    list_purpose: identity_credential_status_core::StatusPurpose,
) -> bool {
    matches!(
        (vc_purpose, list_purpose),
        (
            reallyme_credential::committed::model::StatusPurpose::Revocation,
            identity_credential_status_core::StatusPurpose::Revocation,
        ) | (
            reallyme_credential::committed::model::StatusPurpose::Suspension,
            identity_credential_status_core::StatusPurpose::Suspension,
        )
    )
}

fn enforce_status_binding_sd_jwt(
    env: &CredentialEnvelope,
    status: &StatusContext<'_>,
) -> Result<(), VpValidationError> {
    let expected_id: [u8; 32] = env
        .status
        .status_list_id
        .as_slice()
        .try_into()
        .map_err(|_| VpValidationError::StatusCheckFailed)?;

    if status.index != env.status.status_list_index {
        return Err(VpValidationError::StatusCheckFailed);
    }

    if !purpose_matches_status_core(env.status.purpose, status.list.purpose) {
        return Err(VpValidationError::StatusCheckFailed);
    }

    let got_id = sha256_32(&status.list.encoded_list);
    if got_id != expected_id {
        return Err(VpValidationError::StatusCheckFailed);
    }

    Ok(())
}

#[cfg(test)]
#[path = "validator_compact_jws_tests.rs"]
mod compact_jws_tests;
