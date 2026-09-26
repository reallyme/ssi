// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use core::fmt;
use std::collections::BTreeSet;

use codec_base64url::bytes_to_base64url;
use crypto_sha2_256::digest as sha2_256_digest;
use envelopes_jwk::Jwk;
use envelopes_jwt::jwt::{
    decode_verify_jwt_signature_only_with_header_validation, encode_signed_jwt_with_header_options,
    JwtHeaderEncodeOptions, JwtHeaderValidationOptions,
};
use reallyme_crypto::{core::RngOutputKind, operations::random::fill_bytes as fill_secure_random};
use reallyme_crypto::operations::constant_time::equal as constant_time_equal;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::error::IetfSdJwtVcError;
use crate::process_disclosures::process_sd_jwt_disclosures;
use crate::registered_claims::{
    is_issuer_owned_claim, is_non_selectively_disclosable_claim, SD_JWT_STRUCTURAL_CLAIMS,
};
use crate::validate_temporal_claims::{
    validate_credential_temporal_claims, IetfSdJwtTemporalPolicy,
};
use crate::sensitive::{
    compact_capacity, json_value_within_limits, zeroize_json_value, zeroize_strings,
    MAX_COMPACT_SD_JWT_BYTES, MAX_SD_JWT_DISCLOSURES, MAX_SD_JWT_DISCLOSURE_BYTES,
    MAX_SD_JWT_ISSUER_BYTES, MAX_SD_JWT_JSON_BYTES, MAX_SD_JWT_STRING_BYTES,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelectiveDisclosureStrategy {
    TopLevel,
    AllLevels,
    JsonPaths,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecoyPolicy {
    pub object_decoys: u8,
    pub array_decoys: u8,
}

impl DecoyPolicy {
    pub fn none() -> Self {
        Self {
            object_decoys: 0,
            array_decoys: 0,
        }
    }
}

pub struct Rfc9901IssueInput {
    pub issuer: String,
    pub subject: Option<String>,
    pub issued_at_unix: Option<u64>,
    pub not_before_unix: Option<u64>,
    pub expires_at_unix: Option<u64>,
    pub vct: Option<String>,
    pub confirmation_jwk: Option<Jwk>,
    pub user_claims: Value,
    pub strategy: SelectiveDisclosureStrategy,
    pub custom_json_paths: Vec<String>,
    pub decoys: DecoyPolicy,
}

impl fmt::Debug for Rfc9901IssueInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Rfc9901IssueInput([REDACTED])")
    }
}

impl Zeroize for Rfc9901IssueInput {
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
        zeroize_json_value(&mut self.user_claims);
        zeroize_strings(&mut self.custom_json_paths);
    }
}

impl Drop for Rfc9901IssueInput {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for Rfc9901IssueInput {}

impl Rfc9901IssueInput {
    pub fn new(issuer: impl Into<String>, user_claims: Value) -> Self {
        Self {
            issuer: issuer.into(),
            subject: None,
            issued_at_unix: None,
            not_before_unix: None,
            expires_at_unix: None,
            vct: None,
            confirmation_jwk: None,
            user_claims,
            strategy: SelectiveDisclosureStrategy::TopLevel,
            custom_json_paths: Vec::new(),
            decoys: DecoyPolicy::none(),
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct DisclosureRecord {
    pub path: String,
    pub encoded: String,
    pub digest: String,
}

impl fmt::Debug for DisclosureRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DisclosureRecord([REDACTED])")
    }
}

impl Zeroize for DisclosureRecord {
    fn zeroize(&mut self) {
        self.path.zeroize();
        self.encoded.zeroize();
        self.digest.zeroize();
    }
}

impl Drop for DisclosureRecord {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for DisclosureRecord {}

#[derive(Serialize, Deserialize)]
pub struct SdJwtArtifact {
    pub issuer_signed_jwt: String,
    pub disclosures: Vec<String>,
    pub kb_jwt: Option<String>,
    pub records: Vec<DisclosureRecord>,
}

impl fmt::Debug for SdJwtArtifact {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SdJwtArtifact([REDACTED])")
    }
}

impl Zeroize for SdJwtArtifact {
    fn zeroize(&mut self) {
        self.issuer_signed_jwt.zeroize();
        zeroize_strings(&mut self.disclosures);
        if let Some(value) = &mut self.kb_jwt {
            value.zeroize();
        }
        self.kb_jwt = None;
        for record in &mut self.records {
            record.zeroize();
        }
        self.records.clear();
    }
}

impl Drop for SdJwtArtifact {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for SdJwtArtifact {}

impl SdJwtArtifact {
    pub fn to_compact(&self) -> Result<Zeroizing<String>, IetfSdJwtVcError> {
        let capacity = compact_capacity(
            &self.issuer_signed_jwt,
            &self.disclosures,
            self.kb_jwt.as_deref(),
        )
        .ok_or(IetfSdJwtVcError::InvalidCompactFormat)?;
        let mut out = Zeroizing::new(String::with_capacity(capacity));
        out.push_str(&self.issuer_signed_jwt);
        out.push('~');
        for disclosure in &self.disclosures {
            out.push_str(disclosure);
            out.push('~');
        }
        if let Some(kb) = &self.kb_jwt {
            out.push_str(kb);
        }
        Ok(out)
    }

    pub fn to_json_string(&self) -> Result<Zeroizing<String>, IetfSdJwtVcError> {
        validate_artifact(self, IetfSdJwtVcError::Serialization)?;
        let serialized =
            serde_json::to_string(self).map_err(|_| IetfSdJwtVcError::Serialization)?;
        if serialized.len() > MAX_SD_JWT_JSON_BYTES {
            return Err(IetfSdJwtVcError::Serialization);
        }
        Ok(Zeroizing::new(serialized))
    }

    pub fn from_json_string(json: &str) -> Result<Self, IetfSdJwtVcError> {
        if json.len() > MAX_SD_JWT_JSON_BYTES {
            return Err(IetfSdJwtVcError::Serialization);
        }
        let artifact: Self =
            serde_json::from_str(json).map_err(|_| IetfSdJwtVcError::Serialization)?;
        validate_artifact(&artifact, IetfSdJwtVcError::Serialization)?;
        Ok(artifact)
    }

    pub fn from_compact(compact: &str) -> Result<Self, IetfSdJwtVcError> {
        if compact.len() > MAX_COMPACT_SD_JWT_BYTES
            || compact
                .split('~')
                .count()
                .checked_sub(2)
                .is_none_or(|count| count > MAX_SD_JWT_DISCLOSURES)
        {
            return Err(IetfSdJwtVcError::InvalidCompactFormat);
        }
        let parts: Vec<&str> = compact.split('~').collect();
        if parts.len() < 2 {
            return Err(IetfSdJwtVcError::InvalidCompactFormat);
        }
        let issuer_signed_jwt = parts[0].to_string();
        if issuer_signed_jwt.split('.').count() != 3 {
            return Err(IetfSdJwtVcError::InvalidCompactFormat);
        }

        let trailing_empty = parts.last().map(|s| s.is_empty()).unwrap_or(false);
        let mut disclosures = Vec::new();
        let mut kb_jwt = None;

        if trailing_empty {
            for p in &parts[1..parts.len() - 1] {
                if p.is_empty() {
                    return Err(IetfSdJwtVcError::InvalidCompactFormat);
                }
                disclosures.push((*p).to_string());
            }
        } else {
            if parts.len() < 3 {
                return Err(IetfSdJwtVcError::InvalidCompactFormat);
            }
            for p in &parts[1..parts.len() - 1] {
                if p.is_empty() {
                    return Err(IetfSdJwtVcError::InvalidCompactFormat);
                }
                disclosures.push((*p).to_string());
            }
            kb_jwt = Some(parts[parts.len() - 1].to_string());
        }

        if disclosures.len() > MAX_SD_JWT_DISCLOSURES
            || disclosures
                .iter()
                .any(|value| value.len() > MAX_SD_JWT_DISCLOSURE_BYTES)
            || kb_jwt
                .as_deref()
                .is_some_and(|value| value.split('.').count() != 3)
        {
            return Err(IetfSdJwtVcError::InvalidCompactFormat);
        }

        Ok(Self {
            issuer_signed_jwt,
            disclosures,
            kb_jwt,
            records: Vec::new(),
        })
    }

    pub fn holder_presentation_by_paths(
        &self,
        paths: &[String],
        kb_params: Option<KbJwtBuildParams<'_>>,
    ) -> Result<Self, IetfSdJwtVcError> {
        if self.records.is_empty() && !paths.is_empty() {
            return Err(IetfSdJwtVcError::InvalidInput);
        }

        let mut allowed_owned = BTreeSet::new();
        for p in paths {
            for dep in disclosure_dependencies(p) {
                allowed_owned.insert(dep);
            }
        }
        let allowed: BTreeSet<&str> = allowed_owned.iter().map(String::as_str).collect();
        let mut selected = Vec::new();

        for rec in &self.records {
            if allowed.contains(rec.path.as_str()) {
                selected.push(rec.encoded.clone());
            }
        }

        let mut out = Self {
            issuer_signed_jwt: self.issuer_signed_jwt.clone(),
            disclosures: selected,
            kb_jwt: None,
            records: Vec::new(),
        };

        if let Some(params) = kb_params {
            if params.audience.is_empty() || params.nonce.is_empty() || params.iat_unix == 0 {
                return Err(IetfSdJwtVcError::InvalidInput);
            }
            let compact_without_kb = out.to_compact()?;
            let sd_hash_b64u =
                bytes_to_base64url(sha2_256_digest(compact_without_kb.as_bytes()).as_bytes());
            let payload = serde_json::json!({
                "sd_hash": sd_hash_b64u,
                "aud": params.audience,
                "nonce": params.nonce,
                "iat": params.iat_unix,
            });
            let kb = encode_signed_jwt_with_header_options(
                &payload,
                params.holder_jwk,
                params.holder_private_key,
                &JwtHeaderEncodeOptions::new(Some("kb+jwt".to_string())),
            )
            .map_err(|_| IetfSdJwtVcError::Signature)?;
            out.kb_jwt = Some(kb);
        }

        Ok(out)
    }
}

fn validate_artifact(
    artifact: &SdJwtArtifact,
    error: IetfSdJwtVcError,
) -> Result<(), IetfSdJwtVcError> {
    let compact_is_valid = compact_capacity(
        &artifact.issuer_signed_jwt,
        &artifact.disclosures,
        artifact.kb_jwt.as_deref(),
    )
    .is_some();
    let records_are_valid = artifact.records.len() <= MAX_SD_JWT_DISCLOSURES
        && artifact.records.iter().all(|record| {
            !record.path.is_empty()
                && record.path.len() <= MAX_SD_JWT_STRING_BYTES
                && !record.encoded.is_empty()
                && record.encoded.len() <= MAX_SD_JWT_DISCLOSURE_BYTES
                && !record.digest.is_empty()
                && record.digest.len() <= MAX_SD_JWT_DISCLOSURE_BYTES
        });

    if compact_is_valid && records_are_valid {
        Ok(())
    } else {
        Err(error)
    }
}

pub struct KbJwtBuildParams<'a> {
    pub holder_jwk: &'a Jwk,
    pub holder_private_key: &'a [u8],
    pub audience: &'a str,
    pub nonce: &'a str,
    pub iat_unix: u64,
}

impl fmt::Debug for KbJwtBuildParams<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("KbJwtBuildParams([REDACTED])")
    }
}

pub struct KbJwtVerifyParams<'a> {
    pub holder_jwk: &'a Jwk,
    pub holder_public_key: &'a [u8],
    pub expected_audience: &'a str,
    pub expected_nonce: &'a str,
    pub now_unix: u64,
    /// Maximum age accepted for the mandatory KB-JWT `iat` claim.
    pub max_iat_age_seconds: u64,
    /// Maximum accepted future skew for the KB-JWT `iat` claim.
    pub max_future_iat_skew_seconds: u64,
}

impl fmt::Debug for KbJwtVerifyParams<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("KbJwtVerifyParams([REDACTED])")
    }
}

#[derive(Serialize, Deserialize)]
pub struct VerifiedRfc9901 {
    /// Issuer-signed payload exactly as authenticated.
    pub payload: Value,
    /// Payload with every provided disclosure applied and SD-JWT structural
    /// members removed.
    pub resolved_payload: Value,
    /// Accepted disclosure arrays in original serialization order.
    pub provided_disclosures: Vec<Value>,
}

impl fmt::Debug for VerifiedRfc9901 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("VerifiedRfc9901([REDACTED])")
    }
}

impl Zeroize for VerifiedRfc9901 {
    fn zeroize(&mut self) {
        zeroize_json_value(&mut self.payload);
        zeroize_json_value(&mut self.resolved_payload);
        for disclosure in &mut self.provided_disclosures {
            zeroize_json_value(disclosure);
        }
        self.provided_disclosures.clear();
    }
}

impl Drop for VerifiedRfc9901 {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for VerifiedRfc9901 {}
