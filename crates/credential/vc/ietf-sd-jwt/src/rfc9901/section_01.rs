// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use core::fmt;
use std::collections::BTreeSet;
use std::io::Write;

use codec_base64url::{base64url_to_bytes, bytes_to_base64url};
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

/// Selects which claims become issuer-bound disclosures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelectiveDisclosureStrategy {
    /// Makes each top-level claim selectively disclosable.
    TopLevel,
    /// Recursively makes object members and array elements selectively disclosable.
    AllLevels,
    /// Makes only the configured canonical JSON paths selectively disclosable.
    JsonPaths,
}

/// Controls decoy digest insertion during issuance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecoyPolicy {
    /// Number of decoy digests inserted into each selectively disclosable object.
    pub object_decoys: u8,
    /// Number of decoy digests inserted into each selectively disclosable array.
    pub array_decoys: u8,
}

impl DecoyPolicy {
    /// Constructs a policy with decoy generation disabled.
    pub fn none() -> Self {
        Self {
            object_decoys: 0,
            array_decoys: 0,
        }
    }
}

/// Inputs for RFC 9901 SD-JWT issuance.
pub struct Rfc9901IssueInput {
    /// Issuer identifier written to the authenticated `iss` claim.
    pub issuer: String,
    /// Credential subject covered by the issuer commitment.
    pub subject: Option<String>,
    /// Issuance time encoded as seconds since the Unix epoch.
    pub issued_at_unix: Option<u64>,
    /// Optional `nbf` value, in seconds since the Unix epoch.
    pub not_before_unix: Option<u64>,
    /// Optional `exp` value, in seconds since the Unix epoch.
    pub expires_at_unix: Option<u64>,
    /// Optional verifiable credential type identifier.
    pub vct: Option<String>,
    /// Optional holder key written to the issuer-signed `cnf` claim.
    pub confirmation_jwk: Option<Jwk>,
    /// Claims transformed before the issuer payload is signed.
    pub user_claims: Value,
    /// Disclosure selection strategy.
    pub strategy: SelectiveDisclosureStrategy,
    /// Canonical JSON paths used when `strategy` is `JsonPaths`.
    pub custom_json_paths: Vec<String>,
    /// Decoy digests inserted to obscure the number of real disclosures.
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
    /// Creates issuance input using top-level disclosure and no decoys.
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

/// Records one disclosure, its claim path, and its issuer-bound digest.
#[derive(Serialize, Deserialize)]
pub struct DisclosureRecord {
    /// Canonical claim path associated with the disclosure.
    pub path: String,
    /// Base64url-encoded disclosure exactly as hashed by the issuer.
    pub encoded: String,
    /// Base64url digest that binds the encoded disclosure into the issuer payload.
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

/// Owned RFC 9901 artifact with its issuer JWT and disclosures.
#[derive(Serialize, Deserialize)]
pub struct SdJwtArtifact {
    /// Compact issuer-signed JWT whose signature authenticates the SD-JWT payload.
    pub issuer_signed_jwt: String,
    /// Encoded disclosures carried by this SD-JWT value.
    pub disclosures: Vec<String>,
    /// Optional holder key-binding JWT appended by presentation.
    pub kb_jwt: Option<String>,
    /// Issuance-time metadata used to select disclosures by claim path.
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
    /// Serializes this artifact in RFC 9901 compact form.
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

    /// Serializes this artifact as bounded JSON.
    pub fn to_json_string(&self) -> Result<Zeroizing<String>, IetfSdJwtVcError> {
        validate_artifact(self, IetfSdJwtVcError::Serialization)?;
        let mut writer = BoundedJsonWriter::new(MAX_SD_JWT_JSON_BYTES);
        serde_json::to_writer(&mut writer, self)
            .map_err(|_| IetfSdJwtVcError::Serialization)?;
        writer.into_string()
    }

    /// Parses bounded JSON while rejecting malformed or ambiguous input.
    pub fn from_json_string(json: &str) -> Result<Self, IetfSdJwtVcError> {
        if json.len() > MAX_SD_JWT_JSON_BYTES {
            return Err(IetfSdJwtVcError::Serialization);
        }
        let artifact: Self =
            serde_json::from_str(json).map_err(|_| IetfSdJwtVcError::Serialization)?;
        validate_artifact(&artifact, IetfSdJwtVcError::Serialization)?;
        Ok(artifact)
    }

    /// Parses bounded RFC 9901 compact serialization.
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
        let (issuer, remainder) = parts
            .split_first()
            .ok_or(IetfSdJwtVcError::InvalidCompactFormat)?;
        let (last, middle) = remainder
            .split_last()
            .ok_or(IetfSdJwtVcError::InvalidCompactFormat)?;
        let issuer_signed_jwt = (*issuer).to_string();
        if issuer_signed_jwt.split('.').count() != 3 {
            return Err(IetfSdJwtVcError::InvalidCompactFormat);
        }

        let trailing_empty = last.is_empty();
        let mut disclosures = Vec::new();
        let mut kb_jwt = None;

        if trailing_empty {
            for p in middle {
                if p.is_empty() {
                    return Err(IetfSdJwtVcError::InvalidCompactFormat);
                }
                disclosures.push((*p).to_string());
            }
        } else {
            if parts.len() < 3 {
                return Err(IetfSdJwtVcError::InvalidCompactFormat);
            }
            for p in middle {
                if p.is_empty() {
                    return Err(IetfSdJwtVcError::InvalidCompactFormat);
                }
                disclosures.push((*p).to_string());
            }
            kb_jwt = Some((*last).to_string());
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

    /// Selects disclosures for the requested paths and optionally signs a KB-JWT.
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
            let hash_algorithm = issuer_declared_hash_algorithm(&out.issuer_signed_jwt)?;
            let sd_hash_b64u = hash_algorithm.digest_b64url(&compact_without_kb);
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

struct BoundedJsonWriter {
    bytes: Zeroizing<Vec<u8>>,
    limit: usize,
}

impl BoundedJsonWriter {
    fn new(limit: usize) -> Self {
        Self {
            bytes: Zeroizing::new(Vec::with_capacity(limit)),
            limit,
        }
    }

    fn into_string(mut self) -> Result<Zeroizing<String>, IetfSdJwtVcError> {
        match String::from_utf8(core::mem::take(&mut *self.bytes)) {
            Ok(value) => Ok(Zeroizing::new(value)),
            Err(error) => {
                let mut bytes = error.into_bytes();
                bytes.zeroize();
                Err(IetfSdJwtVcError::Serialization)
            }
        }
    }
}

impl Write for BoundedJsonWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let new_len = self
            .bytes
            .len()
            .checked_add(bytes.len())
            .ok_or_else(|| std::io::Error::other("JSON output limit exceeded"))?;
        if new_len > self.limit {
            return Err(std::io::Error::other("JSON output limit exceeded"));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn issuer_declared_hash_algorithm(
    issuer_signed_jwt: &str,
) -> Result<crate::IetfSdJwtHashAlgorithm, IetfSdJwtVcError> {
    let mut parts = issuer_signed_jwt.split('.');
    let _protected = parts.next().ok_or(IetfSdJwtVcError::InvalidCompactFormat)?;
    let encoded_payload = parts.next().ok_or(IetfSdJwtVcError::InvalidCompactFormat)?;
    let _signature = parts.next().ok_or(IetfSdJwtVcError::InvalidCompactFormat)?;
    if parts.next().is_some() || encoded_payload.len() > MAX_COMPACT_SD_JWT_BYTES {
        return Err(IetfSdJwtVcError::InvalidCompactFormat);
    }
    let payload_bytes = Zeroizing::new(
        base64url_to_bytes(encoded_payload).map_err(|_| IetfSdJwtVcError::InvalidCompactFormat)?,
    );
    if payload_bytes.len() > MAX_SD_JWT_JSON_BYTES {
        return Err(IetfSdJwtVcError::InvalidCompactFormat);
    }
    let mut payload: Value =
        serde_json::from_slice(&payload_bytes).map_err(|_| IetfSdJwtVcError::InvalidInput)?;
    let result = payload
        .as_object()
        .ok_or(IetfSdJwtVcError::InvalidInput)
        .and_then(crate::issue::parse_sd_alg);
    zeroize_json_value(&mut payload);
    result
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
