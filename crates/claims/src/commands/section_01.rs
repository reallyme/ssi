// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::{
    claim_value_from_json, claim_value_from_json_slice, parse_claim_path,
    validate_claim_definition, validate_claim_payload, validate_disclosure, validate_registry,
    ClaimDefinition, ClaimPathEntry, ClaimType, ClaimValue, ClaimsError, ClaimsRegistry,
    DisclosureMode,
};
use serde_json::{Map as JsonMap, Value as JsonValue};
use std::collections::BTreeMap;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Stable outcome for a local claims command.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClaimsCommandOutcome {
    /// Command succeeded.
    Valid,
    /// Command failed validation.
    Invalid,
}

/// Stable sensitivity classification for claim definitions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClaimSensitivity {
    /// Low-risk operational metadata.
    Low,
    /// Ordinary personal data.
    Personal,
    /// High-risk identity, financial, contact, or location data.
    Sensitive,
    /// Special category or strongly protected data.
    SpecialCategory,
}

/// Audit-safe issue emitted by local claim commands.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClaimsCommandIssue {
    /// Typed reason for the failure.
    pub error: ClaimsError,
}

/// Result of validating a claim definition, registry, payload, or disclosure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClaimsValidationResult {
    /// Whether validation succeeded.
    pub valid: bool,
    /// Aggregate command outcome.
    pub outcome: ClaimsCommandOutcome,
    /// Audit-safe validation errors.
    pub errors: Vec<ClaimsCommandIssue>,
}

/// Result of normalizing untrusted claim JSON.
#[derive(PartialEq)]
pub struct ClaimsNormalizeResult {
    /// Normalized, deterministically ordered JSON value.
    pub normalized: JsonValue,
}

/// One claim path mapping from source payload to target payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClaimMapping {
    /// Canonical source claim path, such as `/claims/name/family_name`.
    pub source_path: String,
    /// Canonical target claim path.
    pub target_path: String,
}

/// Result of mapping claims from one profile shape to another.
#[derive(PartialEq)]
pub struct ClaimsMapResult {
    /// Mapped target payload.
    pub claims: JsonValue,
}

/// Result of redacting selected claim paths.
#[derive(PartialEq)]
pub struct ClaimsRedactResult {
    /// Redacted payload.
    pub claims: JsonValue,
}

/// Sensitivity classification for one registered claim.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClaimSensitivityClassification {
    /// Canonical claim identifier.
    pub claim_id: String,
    /// Sensitivity assigned by local deterministic policy.
    pub sensitivity: ClaimSensitivity,
}

/// Result of classifying a registry's claims by sensitivity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClaimsSensitivityResult {
    /// Per-claim classifications in deterministic claim-id order.
    pub claims: Vec<ClaimSensitivityClassification>,
}

/// Localized display row for one registered claim.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalizedClaimDisplay {
    /// Canonical claim identifier.
    pub claim_id: String,
    /// Requested locale echoed for SDK display pipelines.
    pub locale: String,
    /// Deterministic fallback display label derived from the claim identifier.
    pub label: String,
}

/// Result of localizing claim display metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClaimsLocalizeResult {
    /// Per-claim display rows in deterministic claim-id order.
    pub claims: Vec<LocalizedClaimDisplay>,
}

macro_rules! impl_sensitive_json_owner {
    ($($type_name:ty),+ $(,)?) => {
        $(
            impl Zeroize for $type_name {
                fn zeroize(&mut self) {
                    zeroize_json_value(self.claims_or_normalized_mut());
                }
            }

            impl Drop for $type_name {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for $type_name {}

            impl core::fmt::Debug for $type_name {
                fn fmt(
                    &self,
                    formatter: &mut core::fmt::Formatter<'_>,
                ) -> core::fmt::Result {
                    formatter
                        .debug_struct(stringify!($type_name))
                        .field("contents", &"<redacted>")
                        .finish()
                }
            }
        )+
    };
}

trait SensitiveJsonOwner {
    fn claims_or_normalized_mut(&mut self) -> &mut JsonValue;
}

impl SensitiveJsonOwner for ClaimsNormalizeResult {
    fn claims_or_normalized_mut(&mut self) -> &mut JsonValue {
        &mut self.normalized
    }
}

impl SensitiveJsonOwner for ClaimsMapResult {
    fn claims_or_normalized_mut(&mut self) -> &mut JsonValue {
        &mut self.claims
    }
}

impl SensitiveJsonOwner for ClaimsRedactResult {
    fn claims_or_normalized_mut(&mut self) -> &mut JsonValue {
        &mut self.claims
    }
}

impl_sensitive_json_owner!(ClaimsNormalizeResult, ClaimsMapResult, ClaimsRedactResult);

/// Validate a claim definition.
pub fn define_claim(definition: &ClaimDefinition) -> ClaimsValidationResult {
    validation_result(validate_claim_definition(definition))
}

/// Get one claim definition from a registry.
pub fn get_claim_definition<'a>(
    registry: &'a ClaimsRegistry,
    claim_id: &str,
) -> Result<&'a ClaimDefinition, ClaimsError> {
    registry
        .claims
        .get(claim_id)
        .ok_or(ClaimsError::UnknownClaim)
}

/// List claim definitions in deterministic claim-id order.
pub fn list_claim_definitions(registry: &ClaimsRegistry) -> Vec<&ClaimDefinition> {
    registry.claims.values().collect()
}

/// Validate an entire claims registry.
pub fn validate_claims_registry(registry: &ClaimsRegistry) -> ClaimsValidationResult {
    validation_result(validate_registry(registry))
}

/// Validate untrusted JSON claim payload bytes against a registry.
pub fn validate_claims_json_slice(
    registry: &ClaimsRegistry,
    payload_json: &[u8],
) -> ClaimsValidationResult {
    validation_result(
        claim_value_from_json_slice(payload_json)
            .and_then(|payload| validate_claim_payload(registry, &payload)),
    )
}

/// Normalize a JSON claim payload value.
pub fn normalize_claims_json(value: &JsonValue) -> Result<ClaimsNormalizeResult, ClaimsError> {
    let normalized = claim_value_from_json(value)?;
    Ok(ClaimsNormalizeResult {
        normalized: claim_value_to_json(&normalized),
    })
}

/// Normalize JSON claim payload bytes while detecting duplicate object members.
pub fn normalize_claims_json_slice(input: &[u8]) -> Result<ClaimsNormalizeResult, ClaimsError> {
    let normalized = claim_value_from_json_slice(input)?;
    Ok(ClaimsNormalizeResult {
        normalized: claim_value_to_json(&normalized),
    })
}

/// Validate that a requested disclosure is allowed by a registry.
pub fn validate_claim_disclosure(
    registry: &ClaimsRegistry,
    path: &str,
    mode: DisclosureMode,
) -> ClaimsValidationResult {
    validation_result(
        parse_claim_path(path).and_then(|_| validate_disclosure(registry, path, mode)),
    )
}

/// Transform is currently defined as strict normalization for local SDK claims.
pub fn transform_claims_json(value: &JsonValue) -> Result<ClaimsNormalizeResult, ClaimsError> {
    normalize_claims_json(value)
}

/// Map selected claim paths from one payload into a new target payload.
pub fn map_claims_json(
    source: &JsonValue,
    mappings: &[ClaimMapping],
) -> Result<ClaimsMapResult, ClaimsError> {
    let source_value = claim_value_from_json(source)?;
    let mut entries = Vec::with_capacity(mappings.len());

    for mapping in mappings {
        let source_path = parse_claim_path(mapping.source_path.as_str())?;
        let target_path = parse_claim_path(mapping.target_path.as_str())?;
        let value = source_value
            .resolve_path(&source_path)?
            .ok_or(ClaimsError::UnknownClaim)?;
        entries.push(ClaimPathEntry {
            path: target_path,
            value: clone_claim_value(value)?,
        });
    }

    let mapped = crate::claim_value_from_path_entries(entries)?;
    Ok(ClaimsMapResult {
        claims: claim_value_to_json(&mapped),
    })
}

/// Derive a claim payload from canonical path entries.
pub fn derive_claims_from_entries<I>(entries: I) -> Result<ClaimsMapResult, ClaimsError>
where
    I: IntoIterator<Item = ClaimPathEntry>,
{
    let claims = crate::claim_value_from_path_entries(entries)?;
    Ok(ClaimsMapResult {
        claims: claim_value_to_json(&claims),
    })
}

/// Compare two claim payloads after normalization.
pub fn compare_claims_json(left: &JsonValue, right: &JsonValue) -> Result<bool, ClaimsError> {
    let left = claim_value_from_json(left)?;
    let right = claim_value_from_json(right)?;
    Ok(left == right)
}

/// Redact selected canonical claim paths from a JSON payload.
pub fn redact_claims_json(
    payload: &JsonValue,
    redact_paths: &[String],
) -> Result<ClaimsRedactResult, ClaimsError> {
    let mut value = claim_value_from_json(payload)?;
    for path in redact_paths {
        let path = parse_claim_path(path.as_str())?;
        redact_claim_value(&mut value, path.segments())?;
    }
    Ok(ClaimsRedactResult {
        claims: claim_value_to_json(&value),
    })
}

/// Classify a registry's claim definitions by deterministic local sensitivity policy.
pub fn classify_claim_sensitivity(registry: &ClaimsRegistry) -> ClaimsSensitivityResult {
    let claims = registry
        .claims
        .values()
        .map(|definition| ClaimSensitivityClassification {
            claim_id: definition.claim_id.clone(),
            sensitivity: classify_definition(definition),
        })
        .collect();
    ClaimsSensitivityResult { claims }
}

/// Localize claim display rows using deterministic registry-based fallbacks.
///
/// Hosted claim-set metadata can provide richer translations. The local SDK
/// core still needs a stable command for offline callers, so it derives labels
/// from canonical claim identifiers without reaching across the network.
pub fn localize_claims(registry: &ClaimsRegistry, locale: &str) -> ClaimsLocalizeResult {
    let claims = registry
        .claims
        .values()
        .map(|definition| LocalizedClaimDisplay {
            claim_id: definition.claim_id.clone(),
            locale: locale.to_owned(),
            label: fallback_label(definition.claim_id.as_str()),
        })
        .collect();
    ClaimsLocalizeResult { claims }
}

fn validation_result(result: Result<(), ClaimsError>) -> ClaimsValidationResult {
    match result {
        Ok(()) => ClaimsValidationResult {
            valid: true,
            outcome: ClaimsCommandOutcome::Valid,
            errors: Vec::new(),
        },
        Err(error) => ClaimsValidationResult {
            valid: false,
            outcome: ClaimsCommandOutcome::Invalid,
            errors: vec![ClaimsCommandIssue { error }],
        },
    }
}

fn classify_definition(definition: &ClaimDefinition) -> ClaimSensitivity {
    let claim_id = definition.claim_id.as_str();
    if contains_any(
        claim_id,
        &["health", "biometric", "genetic", "religion", "ethnic"],
    ) {
        return ClaimSensitivity::SpecialCategory;
    }
    if contains_any(
        claim_id,
        &[
            "birth",
            "address",
            "passport",
            "license",
            "tax",
            "nationality",
            "email",
            "phone",
            "name",
            "family",
            "given",
        ],
    ) {
        return ClaimSensitivity::Sensitive;
    }
    match definition.claim_type {
        ClaimType::Object | ClaimType::Array | ClaimType::Bytes => ClaimSensitivity::Personal,
        ClaimType::Unspecified | ClaimType::Null => ClaimSensitivity::Low,
        _ => ClaimSensitivity::Personal,
    }
}

fn contains_any(value: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| value.contains(needle))
}

fn fallback_label(claim_id: &str) -> String {
    let mut label = String::with_capacity(claim_id.len());
    let mut capitalize_next = true;
    for byte in claim_id.bytes() {
        match byte {
            b'_' | b'-' | b'/' => {
                label.push(' ');
                capitalize_next = true;
            }
            b'a'..=b'z' if capitalize_next => {
                label.push(char::from(byte - b'a' + b'A'));
                capitalize_next = false;
            }
            _ => {
                label.push(char::from(byte));
                capitalize_next = false;
            }
        }
    }
    label
}

fn redact_claim_value(
    value: &mut ClaimValue,
    path: &[crate::ClaimPathSegment],
) -> Result<(), ClaimsError> {
    let Some((first, rest)) = path.split_first() else {
        *value = ClaimValue::Null;
        return Ok(());
    };

    match (value, first) {
        (ClaimValue::Object(object), crate::ClaimPathSegment::Field(field)) => {
            let target = object.get_mut(field).ok_or(ClaimsError::UnknownClaim)?;
            redact_claim_value(target, rest)
        }
        (ClaimValue::Array(array), crate::ClaimPathSegment::ArrayIndex(index)) => {
            let index = usize::try_from(*index).map_err(|_| {
                ClaimsError::InvalidInput(crate::ClaimsInvalidReason::InvalidClaimPathSegment)
            })?;
            let target = array.get_mut(index).ok_or(ClaimsError::UnknownClaim)?;
            redact_claim_value(target, rest)
        }
        _ => Err(ClaimsError::InvalidInput(
            crate::ClaimsInvalidReason::InvalidClaimPath,
        )),
    }
}
