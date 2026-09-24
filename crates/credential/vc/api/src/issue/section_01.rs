// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use identity_credential_claims_core::{ClaimType, ClaimsRegistry};
use reallyme_credential::committed::issue::IssueInput as CoreIssueInput;
use reallyme_credential::committed::issue::{
    issue_credential, issue_credential_with_signer, OsSaltRng, SaltRng,
};
use reallyme_credential_audit::validate_qeaa_compliance;
use std::collections::BTreeMap;

use crypto_signer::Signer;

use crate::error::{ClaimValueErrorReason, VcApiError};
use crate::model::{
    CredentialProfile, CustomProfile, IssueCredentialRequest, IssuedAndEncoded, IssuedCredential,
    IssuerSigning, PublicFormat,
};

// --------------------------------------------------
// Feature-safe issuer config aliases
// --------------------------------------------------
#[cfg(feature = "jwt")]
use crate::model::JwtIssuerConfig;
#[cfg(not(feature = "jwt"))]
type JwtIssuerConfig = ();

#[cfg(feature = "ietf-sd-jwt")]
use crate::model::IetfSdJwtIssuerConfig;
#[cfg(not(feature = "ietf-sd-jwt"))]
type IetfSdJwtIssuerConfig = ();

#[derive(Clone, Copy)]
pub struct PublicEncoderConfigs<'a> {
    pub jwt: Option<&'a JwtIssuerConfig>,
    pub ietf_sd_jwt: Option<&'a IetfSdJwtIssuerConfig>,
}

impl<'a> PublicEncoderConfigs<'a> {
    pub const fn none() -> Self {
        Self {
            jwt: None,
            ietf_sd_jwt: None,
        }
    }
}

fn validate_claim_type(def_type: ClaimType, v: &serde_json::Value) -> Result<(), VcApiError> {
    use serde_json::Value;
    let invalid_reason = match def_type {
        ClaimType::Unspecified => ClaimValueErrorReason::Unspecified,

        ClaimType::String if matches!(v, Value::String(_)) => return Ok(()),
        ClaimType::String => ClaimValueErrorReason::ExpectedString,
        ClaimType::Boolean if matches!(v, Value::Bool(_)) => return Ok(()),
        ClaimType::Boolean => ClaimValueErrorReason::ExpectedBoolean,

        ClaimType::Integer if matches!(v, Value::Number(n) if n.is_i64() || n.is_u64()) => {
            return Ok(());
        }
        ClaimType::Integer => ClaimValueErrorReason::ExpectedInteger,
        ClaimType::SignedInteger if matches!(v, Value::Number(n) if n.is_i64()) => return Ok(()),
        ClaimType::SignedInteger => ClaimValueErrorReason::ExpectedSignedInteger,
        ClaimType::UnsignedInteger if matches!(v, Value::Number(n) if n.is_u64()) => {
            return Ok(());
        }
        ClaimType::UnsignedInteger => ClaimValueErrorReason::ExpectedUnsignedInteger,

        ClaimType::Number if matches!(v, Value::Number(_)) => return Ok(()),
        ClaimType::Number => ClaimValueErrorReason::ExpectedNumber,
        ClaimType::Decimal if matches!(v, Value::Number(_) | Value::String(_)) => return Ok(()),
        ClaimType::Decimal => ClaimValueErrorReason::ExpectedDecimal,
        ClaimType::Bytes if matches!(v, Value::String(_)) => return Ok(()),
        ClaimType::Bytes => ClaimValueErrorReason::ExpectedBytes,
        ClaimType::Date | ClaimType::DateTime if matches!(v, Value::String(_)) => return Ok(()),
        ClaimType::Date | ClaimType::DateTime => ClaimValueErrorReason::ExpectedDate,
        ClaimType::Null if matches!(v, Value::Null) => return Ok(()),
        ClaimType::Null => ClaimValueErrorReason::ExpectedNull,

        ClaimType::Object if matches!(v, Value::Object(_)) => return Ok(()),
        ClaimType::Object => ClaimValueErrorReason::ExpectedObject,
        ClaimType::Array if matches!(v, Value::Array(_)) => return Ok(()),
        ClaimType::Array => ClaimValueErrorReason::ExpectedArray,
    };

    Err(VcApiError::InvalidClaimValue(invalid_reason))
}

fn validate_claims_against_registry(
    registry: &ClaimsRegistry,
    required_claim_ids: &[String],
    claims: &BTreeMap<String, serde_json::Value>,
) -> Result<(), VcApiError> {
    // required claims
    for req in required_claim_ids {
        if !claims.contains_key(req) {
            return Err(VcApiError::MissingRequiredClaim);
        }
    }

    // validate each claim id exists + type matches
    for (claim_id, v) in claims {
        let def = registry
            .claims
            .get(claim_id)
            .ok_or(VcApiError::ClaimsRegistry(
                identity_credential_claims_core::ClaimsError::UnknownClaim,
            ))?;

        validate_claim_type(def.claim_type, v)?;
    }

    Ok(())
}

/// Issue a VC using caller-provided RNG (deterministic tests, etc).
pub fn issue_with_rng<R: SaltRng>(
    req: IssueCredentialRequest,
    signing: &IssuerSigning,
    rng: &mut R,
    now_unix: u64,
) -> Result<IssuedCredential, VcApiError> {
    let (core_in, claims) = prepare_issue_request(req, now_unix)?;

    let issued = issue_credential(
        core_in,
        &claims,
        signing.alg,
        signing.private_key_bytes(),
        rng,
    )?;

    Ok(IssuedCredential {
        envelope: issued.envelope,
        subject_bundle: issued.subject_bundle,
    })
}

/// Issue a VC using an abstract signer (HSM/QSCD/remote signing friendly).
pub fn issue_with_signer_with_rng<R: SaltRng>(
    req: IssueCredentialRequest,
    signer: &dyn Signer,
    rng: &mut R,
    now_unix: u64,
) -> Result<IssuedCredential, VcApiError> {
    let (core_in, claims) = prepare_issue_request(req, now_unix)?;

    let issued = issue_credential_with_signer(core_in, &claims, signer, rng)
        .map_err(|_| VcApiError::IssuanceFailed)?;

    Ok(IssuedCredential {
        envelope: issued.envelope,
        subject_bundle: issued.subject_bundle,
    })
}

/// Convenience issuance using OS RNG.
pub fn issue_with_os_rng(
    req: IssueCredentialRequest,
    signing: &IssuerSigning,
    now_unix: u64,
) -> Result<IssuedCredential, VcApiError> {
    let mut rng = OsSaltRng;
    issue_with_rng(req, signing, &mut rng, now_unix)
}

/// Convenience issuance using OS RNG + abstract signer.
pub fn issue_with_signer_with_os_rng(
    req: IssueCredentialRequest,
    signer: &dyn Signer,
    now_unix: u64,
) -> Result<IssuedCredential, VcApiError> {
    let mut rng = OsSaltRng;
    issue_with_signer_with_rng(req, signer, &mut rng, now_unix)
}

/// Issue + encode the public credential.
pub fn issue_and_encode_with_rng<R: SaltRng>(
    req: IssueCredentialRequest,
    signing: &IssuerSigning,
    rng: &mut R,
    now_unix: u64,
    public_format: PublicFormat,
    encoder_cfgs: PublicEncoderConfigs<'_>,
) -> Result<IssuedAndEncoded, VcApiError> {
    // Keep optional encoder config arguments referenced across feature-gated builds.
    #[cfg(not(feature = "jwt"))]
    let _ = &encoder_cfgs.jwt;

    #[cfg(not(feature = "ietf-sd-jwt"))]
    let _ = &encoder_cfgs.ietf_sd_jwt;

    let (core_in, issued_claims) = prepare_issue_request(req, now_unix)?;
    let issued = issue_credential(
        core_in,
        &issued_claims,
        signing.alg,
        signing.private_key_bytes(),
        rng,
    )?;
    let public_bytes = match public_format {
        PublicFormat::JwtVc => {
            #[cfg(feature = "jwt")]
            {
                let cfg = encoder_cfgs.jwt.ok_or(VcApiError::EncoderNotAvailable)?;
                let subject_id =
                    encoded_party_reference(&issued.envelope.subject.subject_reference)
                        .ok_or(VcApiError::EncodingFailed)?;
                let jwt = identity_vc_jwt::encode_vc_jwt(
                    &issued.envelope,
                    &cfg.issuer_did,
                    subject_id,
                    &cfg.issuer_jwk,
                    signing.private_key_bytes(),
                    None,
                )
                .map_err(|_| VcApiError::EncodingFailed)?;
                jwt.into_bytes()
            }
            #[cfg(not(feature = "jwt"))]
            {
                return Err(VcApiError::EncoderNotAvailable);
            }
        }

        PublicFormat::IetfSdJwtVc => {
            #[cfg(feature = "ietf-sd-jwt")]
            {
                let cfg = encoder_cfgs
                    .ietf_sd_jwt
                    .ok_or(VcApiError::EncoderNotAvailable)?;
                let input = ietf_sd_jwt_input_from_envelope(
                    &issued.envelope,
                    &issued_claims,
                    cfg,
                    now_unix,
                )?;
                let out = identity_vc_ietf_sd_jwt::issue_ietf_sd_jwt_vc(
                    &input,
                    &cfg.issuer_jwk,
                    signing.private_key_bytes(),
                )
                .map_err(|_| VcApiError::EncodingFailed)?;
                let mut compact = out.to_compact().map_err(|_| VcApiError::EncodingFailed)?;
                core::mem::take(&mut *compact).into_bytes()
            }
            #[cfg(not(feature = "ietf-sd-jwt"))]
            {
                return Err(VcApiError::EncoderNotAvailable);
            }
        }
    };

    Ok(IssuedAndEncoded {
        public_format,
        public_bytes,
        envelope: issued.envelope,
        subject_bundle: issued.subject_bundle,
    })
}

/// Issue + encode the public credential using an abstract signer (HSM/QSCD/remote-sign friendly).
pub fn issue_and_encode_with_signer_with_rng<R: SaltRng>(
    req: IssueCredentialRequest,
    signer: &dyn Signer,
    rng: &mut R,
    now_unix: u64,
    public_format: PublicFormat,
    encoder_cfgs: PublicEncoderConfigs<'_>,
) -> Result<IssuedAndEncoded, VcApiError> {
    // Keep optional encoder config arguments referenced across feature-gated builds.
    #[cfg(not(feature = "jwt"))]
    let _ = &encoder_cfgs.jwt;

    #[cfg(not(feature = "ietf-sd-jwt"))]
    let _ = &encoder_cfgs.ietf_sd_jwt;

    let (core_in, issued_claims) = prepare_issue_request(req, now_unix)?;
    let issued = issue_credential_with_signer(core_in, &issued_claims, signer, rng)
        .map_err(|_| VcApiError::IssuanceFailed)?;
    let public_bytes = match public_format {
        PublicFormat::JwtVc => {
            #[cfg(feature = "jwt")]
            {
                let cfg = encoder_cfgs.jwt.ok_or(VcApiError::EncoderNotAvailable)?;
                let subject_id =
                    encoded_party_reference(&issued.envelope.subject.subject_reference)
                        .ok_or(VcApiError::EncodingFailed)?;
                let jwt = identity_vc_jwt::encode_vc_jwt_with_signer(
                    &issued.envelope,
                    &cfg.issuer_did,
                    subject_id,
                    &cfg.issuer_jwk,
                    signer,
                    None,
                )
                .map_err(|_| VcApiError::EncodingFailed)?;
                jwt.into_bytes()
            }
            #[cfg(not(feature = "jwt"))]
            {
                return Err(VcApiError::EncoderNotAvailable);
            }
        }

        PublicFormat::IetfSdJwtVc => {
            #[cfg(feature = "ietf-sd-jwt")]
            {
                let cfg = encoder_cfgs
                    .ietf_sd_jwt
                    .ok_or(VcApiError::EncoderNotAvailable)?;
                let input = ietf_sd_jwt_input_from_envelope(
                    &issued.envelope,
                    &issued_claims,
                    cfg,
                    now_unix,
                )?;
                let out = identity_vc_ietf_sd_jwt::issue_ietf_sd_jwt_vc_with_signer(
                    &input,
                    &cfg.issuer_jwk,
                    signer,
                )
                .map_err(|_| VcApiError::EncodingFailed)?;
                let mut compact = out.to_compact().map_err(|_| VcApiError::EncodingFailed)?;
                core::mem::take(&mut *compact).into_bytes()
            }
            #[cfg(not(feature = "ietf-sd-jwt"))]
            {
                return Err(VcApiError::EncoderNotAvailable);
            }
        }
    };

    Ok(IssuedAndEncoded {
        public_format,
        public_bytes,
        envelope: issued.envelope,
        subject_bundle: issued.subject_bundle,
    })
}

/// Convenience: issue+encode using OS RNG.
pub fn issue_and_encode_with_os_rng(
    req: IssueCredentialRequest,
    signing: &IssuerSigning,
    now_unix: u64,
    public_format: PublicFormat,
    encoder_cfgs: PublicEncoderConfigs<'_>,
) -> Result<IssuedAndEncoded, VcApiError> {
    let mut rng = OsSaltRng;
    issue_and_encode_with_rng(
        req,
        signing,
        &mut rng,
        now_unix,
        public_format,
        encoder_cfgs,
    )
}

/// Convenience: issue+encode using OS RNG + abstract signer.
pub fn issue_and_encode_with_signer_with_os_rng(
    req: IssueCredentialRequest,
    signer: &dyn Signer,
    now_unix: u64,
    public_format: PublicFormat,
    encoder_cfgs: PublicEncoderConfigs<'_>,
) -> Result<IssuedAndEncoded, VcApiError> {
    let mut rng = OsSaltRng;
    issue_and_encode_with_signer_with_rng(
        req,
        signer,
        &mut rng,
        now_unix,
        public_format,
        encoder_cfgs,
    )
}

// -----------------------------------------------------------------------------
// Small helpers
// -----------------------------------------------------------------------------
