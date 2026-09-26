// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Web / QR delivery-layer validation boundary.
//!
//! This module performs **cryptographic** VP/VC verification suitable for verifier-grade deployments:
//! - SD-JWT VC issuer signature verification
//! - Credential envelope issuer signature and `sd_hash` envelope binding
//! - Claimset binding between the selected policy and the signed envelope
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
use identity_presentation_vp_sd_jwt::{verify_sd_jwt_vp_with_binding, ExpectedKbJwtBinding};

use reallyme_credential::committed::model::{
    CredentialEnvelope, HolderBinding, PublicKeyRepresentation,
};
use reallyme_credential::{verify_credential_status, CredentialError, CredentialStatusReason};
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
/// - QEAA evidence and holder-binding results are NOT supplied; they are
///   derived from the issuer-bound credential envelope and the verified KB-JWT
pub struct WebValidationInput<'a> {
    /// Presentation received at the delivery boundary.
    pub presentation: &'a Presentation,
    /// Claim registry used to validate disclosed claim semantics.
    pub claims_registry: &'a ClaimsRegistry,
    /// Claimset identifier expected for this verification policy.
    ///
    /// The issuer-signed envelope `profile_id` must equal this value.
    pub claimset_id: &'a str,
    /// Optional status context supplied by the caller.
    ///
    /// The status list must be the one referenced by the envelope: same
    /// issuer, purpose, list identifier, and index.
    pub status: Option<StatusContext<'a>>,

    /// Typed credential envelope for cryptographic verification of SD-JWT and ZK presentations.
    pub credential_envelope: Option<&'a CredentialEnvelope>,

    /// Issuer public key for SD-JWT VC signature verification (raw bytes).
    pub sd_jwt_issuer_public_key: Option<&'a [u8]>,

    /// Exact relying-party binding required for a holder-bound SD-JWT VC.
    ///
    /// Audience, nonce, trusted time, and maximum age are verified together
    /// with the holder signature. Web delivery has no other holder-binding
    /// proof, so omitting this fails closed. `now_unix` must equal
    /// [`WebValidationInput::now_unix`].
    pub sd_jwt_binding: Option<ExpectedKbJwtBinding<'a>>,

    /// Current trusted verifier time as Unix seconds.
    pub now_unix: u64,
}

/// Validate a VP received via a Web / QR / direct channel at the **delivery boundary**.
pub fn validate_web_presentation<'a>(
    input: WebValidationInput<'a>,
) -> Result<WebValidationResult, VpValidationError> {
    let verified = verify_presentation_crypto(&input)?;

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
        qeaa: QeaaContext {
            qeaa_from_vc: verified.envelope.qeaa_compliance.as_ref(),
        },
        binding_ok: verified.holder_binding_verified,
        now_unix: input.now_unix,
    })?;

    Ok(match decision {
        PolicyDecision::Accept => WebValidationResult::Accepted,
        PolicyDecision::Reject(errs) => WebValidationResult::Rejected(errs),
    })
}

/// Facts established by cryptographic verification of the presentation.
struct VerifiedWebPresentation<'a> {
    /// Issuer-signed envelope bound to the issuer SD-JWT `sd_hash`.
    envelope: &'a CredentialEnvelope,
    /// Whether a KB-JWT was verified against the envelope holder key and the
    /// relying-party audience, nonce, and trusted time.
    holder_binding_verified: bool,
}

fn verify_presentation_crypto<'a>(
    input: &WebValidationInput<'a>,
) -> Result<VerifiedWebPresentation<'a>, VpValidationError> {
    match input.presentation {
        Presentation::SdJwtVc(sd) => {
            let env = input
                .credential_envelope
                .ok_or(VpValidationError::MissingCredentialEnvelope)?;

            enforce_claimset_binding(env, input.claimset_id)?;

            let issuer_pk = input
                .sd_jwt_issuer_public_key
                .ok_or_else(policy_misconfig)?;

            let issuer_algorithm = extract_jws_algorithm(&sd.sd_jwt)?;
            let issuer_jwk = jwk_for_algorithm_and_public_key(issuer_algorithm, issuer_pk)?;

            let holder_pk = match &env.subject.holder_binding {
                HolderBinding::CryptographicKey(key) => match &key.public_key {
                    PublicKeyRepresentation::Raw { bytes, .. } => bytes.as_slice(),
                    _ => return Err(policy_misconfig()),
                },
                // Web delivery can only verify key-based holder binding.
                // Claims-based binding needs an out-of-band verification this
                // boundary does not perform, and bearer credentials carry no
                // relying-party binding at all; neither may be reported as
                // bound.
                HolderBinding::ClaimsBased(_) | HolderBinding::BearerWithoutBinding => {
                    return Err(VpValidationError::InvalidBinding);
                }
            };

            let binding = input.sd_jwt_binding.ok_or_else(proof_invalid)?;
            if binding.now_unix != input.now_unix || sd.kb_jwt.is_none() {
                return Err(proof_invalid());
            }

            // Verifies the issuer SD-JWT, binds `env` to its `sd_hash`,
            // verifies the envelope issuer signature, the KB-JWT, and every
            // Merkle disclosure.
            verify_sd_jwt_vp_with_binding(
                sd,
                env,
                &issuer_jwk,
                issuer_pk,
                Some(holder_pk),
                binding,
            )
            .map_err(|_| proof_invalid())?;

            // Status pointer fields are only trusted after the envelope has
            // been bound to the issuer signature above.
            if let Some(status) = input.status.as_ref() {
                enforce_status_binding_sd_jwt(env, status, input.now_unix)?;
            }

            Ok(VerifiedWebPresentation {
                envelope: env,
                holder_binding_verified: true,
            })
        }

        Presentation::Zk(_) => Err(VpValidationError::PolicyRejected(vec![
            VpPolicyError::PresentationFormatNotAllowed,
        ])),

        Presentation::Mdoc(_) => Err(VpValidationError::PolicyRejected(vec![
            VpPolicyError::PresentationFormatNotAllowed,
        ])),
    }
}

fn enforce_claimset_binding(
    env: &CredentialEnvelope,
    claimset_id: &str,
) -> Result<(), VpValidationError> {
    // The caller-selected claimset chooses the verifier policy; it must be
    // the claimset the issuer actually signed into the envelope.
    if env.profile_id != claimset_id || env.claims_commitment.claimset_id != claimset_id {
        return Err(VpValidationError::PolicyRejected(vec![
            VpPolicyError::ClaimsetNotAllowed,
        ]));
    }
    Ok(())
}

fn proof_invalid() -> VpValidationError {
    VpValidationError::PolicyRejected(vec![VpPolicyError::ProofInvalid])
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

/// Bind the caller-supplied status list to the envelope's status pointer.
///
/// The pointer rule (issuer, purpose, list identifier) is owned by
/// `reallyme-credential`; revocation and suspension results are left to policy
/// evaluation so they surface as typed policy rejections.
fn enforce_status_binding_sd_jwt(
    env: &CredentialEnvelope,
    status: &StatusContext<'_>,
    now_unix: u64,
) -> Result<(), VpValidationError> {
    if status.index != env.status.status_list_index {
        return Err(VpValidationError::StatusCheckFailed);
    }

    match verify_credential_status(env, status.list, now_unix, status.verifier) {
        Ok(())
        | Err(CredentialError::Status(
            CredentialStatusReason::Revoked | CredentialStatusReason::Suspended,
        )) => Ok(()),
        Err(_) => Err(VpValidationError::StatusCheckFailed),
    }
}

#[cfg(test)]
#[path = "validator_compact_jws_tests.rs"]
mod compact_jws_tests;
