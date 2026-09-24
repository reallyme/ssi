// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use core::fmt;
use std::collections::BTreeSet;

use codec_base64url::bytes_to_base64url;
use crypto_sha2_256::digest as sha2_256_digest;
use crypto_signer::Signer;
use envelopes_jwk::Jwk;
use envelopes_jwt::jwt::{
    encode_signed_jwt_with_header_options, encode_signed_jwt_with_signer_and_header_options,
    JwtHeaderEncodeOptions,
};
use reallyme_crypto::{core::RngOutputKind, operations::random::fill_bytes as fill_secure_random};
use serde_json::{Map, Value};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::me_profile::{insert_me_profile_merkle_binding, MeProfileMerkleBinding};
use crate::sensitive::{
    compact_capacity, json_value_within_limits, zeroize_json_map, zeroize_strings,
    MAX_SD_JWT_DISCLOSURES, MAX_SD_JWT_ISSUER_BYTES, MAX_SD_JWT_SALT_BYTES,
};
use crate::{error::IetfSdJwtVcError, payload::SdJwtDisclosure};

const RESERVED_KEYS: [&str; 2] = ["_sd", "_sd_alg"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IetfSdJwtHashAlgorithm {
    Sha256,
}

impl IetfSdJwtHashAlgorithm {
    fn as_str(self) -> &'static str {
        match self {
            Self::Sha256 => "sha-256",
        }
    }

    fn digest_b64url(self, disclosure_b64u: &str) -> String {
        match self {
            Self::Sha256 => {
                bytes_to_base64url(sha2_256_digest(disclosure_b64u.as_bytes()).as_bytes())
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IetfSdJwtJwtType {
    DcSdJwt,
    VcSdJwt,
    Jwt,
}

impl IetfSdJwtJwtType {
    fn as_str(self) -> &'static str {
        match self {
            Self::DcSdJwt => "dc+sd-jwt",
            Self::VcSdJwt => "vc+sd-jwt",
            Self::Jwt => "JWT",
        }
    }
}

pub struct IetfSdJwtIssueInput {
    pub issuer: String,
    pub subject: Option<String>,
    pub issued_at_unix: Option<u64>,
    pub not_before_unix: Option<u64>,
    pub expires_at_unix: Option<u64>,
    pub vct: Option<String>,
    pub confirmation_jwk: Option<Jwk>,
    pub me_profile_merkle_binding: Option<MeProfileMerkleBinding>,
    pub public_claims: Map<String, Value>,
    pub selective_claims: Map<String, Value>,
    pub hash_algorithm: IetfSdJwtHashAlgorithm,
    pub jwt_type: IetfSdJwtJwtType,
    pub salt_len: usize,
}

impl fmt::Debug for IetfSdJwtIssueInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("IetfSdJwtIssueInput([REDACTED])")
    }
}

impl Zeroize for IetfSdJwtIssueInput {
    fn zeroize(&mut self) {
        self.issuer.zeroize();
        if let Some(value) = &mut self.subject {
            value.zeroize();
        }
        self.subject = None;
        if let Some(value) = &mut self.vct {
            value.zeroize();
        }
        self.vct = None;
        if let Some(binding) = &mut self.me_profile_merkle_binding {
            binding.zeroize();
        }
        self.me_profile_merkle_binding = None;
        zeroize_json_map(&mut self.public_claims);
        zeroize_json_map(&mut self.selective_claims);
    }
}

impl Drop for IetfSdJwtIssueInput {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for IetfSdJwtIssueInput {}

impl IetfSdJwtIssueInput {
    pub fn new(issuer: impl Into<String>) -> Self {
        Self {
            issuer: issuer.into(),
            subject: None,
            issued_at_unix: None,
            not_before_unix: None,
            expires_at_unix: None,
            vct: None,
            confirmation_jwk: None,
            me_profile_merkle_binding: None,
            public_claims: Map::new(),
            selective_claims: Map::new(),
            hash_algorithm: IetfSdJwtHashAlgorithm::Sha256,
            jwt_type: IetfSdJwtJwtType::DcSdJwt,
            salt_len: 16,
        }
    }
}

pub struct IetfSdJwtIssueOutput {
    pub issuer_signed_jwt: String,
    pub disclosures: Vec<String>,
    pub disclosures_decoded: Vec<SdJwtDisclosure>,
}

impl fmt::Debug for IetfSdJwtIssueOutput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("IetfSdJwtIssueOutput([REDACTED])")
    }
}

impl Zeroize for IetfSdJwtIssueOutput {
    fn zeroize(&mut self) {
        self.issuer_signed_jwt.zeroize();
        zeroize_strings(&mut self.disclosures);
        for disclosure in &mut self.disclosures_decoded {
            disclosure.zeroize();
        }
        self.disclosures_decoded.clear();
    }
}

impl Drop for IetfSdJwtIssueOutput {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for IetfSdJwtIssueOutput {}

impl IetfSdJwtIssueOutput {
    /// Compact SD-JWT serialization used for issuance / transfer.
    ///
    /// Shape: `<issuer-signed-jwt>~<disclosure>~...~`
    pub fn to_compact(&self) -> Result<Zeroizing<String>, IetfSdJwtVcError> {
        let capacity = compact_capacity(&self.issuer_signed_jwt, &self.disclosures, None)
            .ok_or(IetfSdJwtVcError::InvalidCompactFormat)?;
        let mut out = Zeroizing::new(String::with_capacity(capacity));
        out.push_str(&self.issuer_signed_jwt);
        out.push('~');
        for disclosure in &self.disclosures {
            out.push_str(disclosure);
            out.push('~');
        }
        Ok(out)
    }
}

pub fn issue_ietf_sd_jwt_vc(
    input: &IetfSdJwtIssueInput,
    issuer_jwk: &Jwk,
    issuer_private_key: &[u8],
) -> Result<IetfSdJwtIssueOutput, IetfSdJwtVcError> {
    let mut rng = OsSaltRng;
    issue_ietf_sd_jwt_vc_with_rng(input, issuer_jwk, issuer_private_key, &mut rng)
}

/// Issue an IETF SD-JWT VC using deterministic salt generation.
///
/// This API exists for conformance vectors and golden fixtures.
/// It MUST NOT be used in production issuance flows.
#[cfg(feature = "conformance-vectors")]
pub fn issue_ietf_sd_jwt_vc_deterministic(
    input: &IetfSdJwtIssueInput,
    issuer_jwk: &Jwk,
    issuer_private_key: &[u8],
    salt_seed: u64,
) -> Result<IetfSdJwtIssueOutput, IetfSdJwtVcError> {
    let mut rng = DeterministicSaltRng::new(salt_seed);
    issue_ietf_sd_jwt_vc_with_rng(input, issuer_jwk, issuer_private_key, &mut rng)
}

pub fn issue_ietf_sd_jwt_vc_with_signer(
    input: &IetfSdJwtIssueInput,
    issuer_jwk: &Jwk,
    signer: &dyn Signer,
) -> Result<IetfSdJwtIssueOutput, IetfSdJwtVcError> {
    let mut rng = OsSaltRng;
    issue_ietf_sd_jwt_vc_with_signer_and_rng(input, issuer_jwk, signer, &mut rng)
}

/// Issue an IETF SD-JWT VC using deterministic salt generation and signer abstraction.
///
/// This API exists for conformance vectors and golden fixtures.
/// It MUST NOT be used in production issuance flows.
#[cfg(feature = "conformance-vectors")]
pub fn issue_ietf_sd_jwt_vc_with_signer_deterministic(
    input: &IetfSdJwtIssueInput,
    issuer_jwk: &Jwk,
    signer: &dyn Signer,
    salt_seed: u64,
) -> Result<IetfSdJwtIssueOutput, IetfSdJwtVcError> {
    let mut rng = DeterministicSaltRng::new(salt_seed);
    issue_ietf_sd_jwt_vc_with_signer_and_rng(input, issuer_jwk, signer, &mut rng)
}

pub(crate) trait SaltRng {
    fn fill_bytes(&mut self, out: &mut [u8]) -> Result<(), IetfSdJwtVcError>;
}

struct OsSaltRng;

impl SaltRng for OsSaltRng {
    fn fill_bytes(&mut self, out: &mut [u8]) -> Result<(), IetfSdJwtVcError> {
        fill_secure_random(out, RngOutputKind::Generic).map_err(|_| IetfSdJwtVcError::InvalidInput)
    }
}

#[derive(Debug, Clone)]
#[cfg(feature = "conformance-vectors")]
struct DeterministicSaltRng {
    state: u64,
}

#[cfg(feature = "conformance-vectors")]
impl DeterministicSaltRng {
    fn new(seed: u64) -> Self {
        // Avoid all-zero xorshift64* state.
        let state = if seed == 0 {
            0x9E37_79B9_7F4A_7C15
        } else {
            seed
        };
        Self { state }
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.state = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
}

#[cfg(feature = "conformance-vectors")]
impl SaltRng for DeterministicSaltRng {
    fn fill_bytes(&mut self, out: &mut [u8]) -> Result<(), IetfSdJwtVcError> {
        let mut offset = 0usize;
        while offset < out.len() {
            let block = self.next_u64().to_le_bytes();
            let remaining = out.len() - offset;
            let take = remaining.min(block.len());
            out[offset..offset + take].copy_from_slice(&block[..take]);
            offset += take;
        }
        Ok(())
    }
}

pub(crate) fn issue_ietf_sd_jwt_vc_with_rng<R: SaltRng>(
    input: &IetfSdJwtIssueInput,
    issuer_jwk: &Jwk,
    issuer_private_key: &[u8],
    rng: &mut R,
) -> Result<IetfSdJwtIssueOutput, IetfSdJwtVcError> {
    validate_issue_input(input)?;

    let mut payload = build_common_payload(input)?;

    if !input.selective_claims.is_empty() {
        let mut digests: Vec<String> = Vec::with_capacity(input.selective_claims.len());

        let mut disclosures = Vec::with_capacity(input.selective_claims.len());
        let mut disclosures_decoded = Vec::with_capacity(input.selective_claims.len());

        for (key, value) in &input.selective_claims {
            let disclosure = build_disclosure(key, value.clone(), input.salt_len, rng)?;
            let disclosure_bytes = Zeroizing::new(
                serde_json::to_vec(&[
                    Value::String(disclosure.salt_b64u.clone()),
                    Value::String(disclosure.key.clone()),
                    disclosure.value.clone(),
                ])
                .map_err(|_| IetfSdJwtVcError::Serialization)?,
            );
            let disclosure_b64u = bytes_to_base64url(&disclosure_bytes);
            let digest = input.hash_algorithm.digest_b64url(&disclosure_b64u);

            digests.push(digest);
            disclosures.push(disclosure_b64u);
            disclosures_decoded.push(disclosure);
        }

        // Deterministic ordering helps cross-platform reproducibility.
        digests.sort();

        payload.insert(
            "_sd".to_string(),
            Value::Array(digests.into_iter().map(Value::String).collect()),
        );
        payload.insert(
            "_sd_alg".to_string(),
            Value::String(input.hash_algorithm.as_str().to_string()),
        );

        let issuer_signed_jwt = issue_jwt_with_typ(
            &Value::Object(payload),
            issuer_jwk,
            issuer_private_key,
            input.jwt_type,
        )?;

        return checked_issue_output(IetfSdJwtIssueOutput {
            issuer_signed_jwt,
            disclosures,
            disclosures_decoded,
        });
    }

    let issuer_signed_jwt = issue_jwt_with_typ(
        &Value::Object(payload),
        issuer_jwk,
        issuer_private_key,
        input.jwt_type,
    )?;

    checked_issue_output(IetfSdJwtIssueOutput {
        issuer_signed_jwt,
        disclosures: Vec::new(),
        disclosures_decoded: Vec::new(),
    })
}

pub(crate) fn issue_ietf_sd_jwt_vc_with_signer_and_rng<R: SaltRng>(
    input: &IetfSdJwtIssueInput,
    issuer_jwk: &Jwk,
    signer: &dyn Signer,
    rng: &mut R,
) -> Result<IetfSdJwtIssueOutput, IetfSdJwtVcError> {
    validate_issue_input(input)?;

    let mut payload = build_common_payload(input)?;

    let mut disclosures = Vec::new();
    let mut disclosures_decoded = Vec::new();

    if !input.selective_claims.is_empty() {
        let mut digests: Vec<String> = Vec::with_capacity(input.selective_claims.len());

        for (key, value) in &input.selective_claims {
            let disclosure = build_disclosure(key, value.clone(), input.salt_len, rng)?;
            let disclosure_bytes = Zeroizing::new(
                serde_json::to_vec(&[
                    Value::String(disclosure.salt_b64u.clone()),
                    Value::String(disclosure.key.clone()),
                    disclosure.value.clone(),
                ])
                .map_err(|_| IetfSdJwtVcError::Serialization)?,
            );
            let disclosure_b64u = bytes_to_base64url(&disclosure_bytes);
            let digest = input.hash_algorithm.digest_b64url(&disclosure_b64u);

            digests.push(digest);
            disclosures.push(disclosure_b64u);
            disclosures_decoded.push(disclosure);
        }

        digests.sort();

        payload.insert(
            "_sd".to_string(),
            Value::Array(digests.into_iter().map(Value::String).collect()),
        );
        payload.insert(
            "_sd_alg".to_string(),
            Value::String(input.hash_algorithm.as_str().to_string()),
        );
    }

    let issuer_signed_jwt = issue_jwt_with_typ_using_signer(
        &Value::Object(payload),
        issuer_jwk,
        signer,
        input.jwt_type,
    )?;

    checked_issue_output(IetfSdJwtIssueOutput {
        issuer_signed_jwt,
        disclosures,
        disclosures_decoded,
    })
}

fn checked_issue_output(
    output: IetfSdJwtIssueOutput,
) -> Result<IetfSdJwtIssueOutput, IetfSdJwtVcError> {
    compact_capacity(&output.issuer_signed_jwt, &output.disclosures, None)
        .ok_or(IetfSdJwtVcError::InvalidCompactFormat)?;
    Ok(output)
}
