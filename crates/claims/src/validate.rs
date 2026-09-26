// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::{
    claim_id_from_path, escape_field_segment, is_valid_claim_id, parse_claim_path, ClaimDefinition,
    ClaimPath, ClaimType, ClaimValue, ClaimsError, ClaimsInvalidReason, ClaimsRegistry,
    DisclosureMode,
};
use std::collections::{BTreeMap, BTreeSet};

/// Maximum claim definitions in one registry.
pub const MAX_CLAIMS_PER_REGISTRY: usize = 512;

/// Maximum UTF-8 bytes in a canonical claim identifier.
pub const MAX_CLAIM_ID_BYTES: usize = 256;

/// Maximum predicate disclosure modes per claim definition.
pub const MAX_DISCLOSURE_PREDICATES: usize = 16;

/// Validate an entire claims registry.
pub fn validate_registry(registry: &ClaimsRegistry) -> Result<(), ClaimsError> {
    if registry.claimset_id.trim().is_empty() {
        return Err(ClaimsError::InvalidInput(
            ClaimsInvalidReason::EmptyClaimsetId,
        ));
    }
    if registry.claims.len() > MAX_CLAIMS_PER_REGISTRY {
        return Err(ClaimsError::InvalidInput(
            ClaimsInvalidReason::TooManyClaims,
        ));
    }
    let mut parsed_paths = Vec::with_capacity(registry.claims.len());
    for (key, claim) in &registry.claims {
        validate_claim_definition(claim)?;
        if key != &claim.claim_id {
            return Err(ClaimsError::InvalidInput(
                ClaimsInvalidReason::ClaimKeyMismatch,
            ));
        }
        let path = claim_path_for_id(claim.claim_id.as_str())?;
        parsed_paths.push(path);
    }
    validate_no_parent_child_conflicts(parsed_paths.as_slice())?;

    Ok(())
}

/// Reject registries where one claim path is a strict ancestor of another.
///
/// Uses a set of canonical ancestor identifiers so the check scales with the
/// total number of path segments instead of pairwise over every claim.
fn validate_no_parent_child_conflicts(paths: &[ClaimPath]) -> Result<(), ClaimsError> {
    let mut ancestors = BTreeSet::new();
    for path in paths {
        ancestors.extend(path.strict_ancestor_claim_ids());
    }
    for path in paths {
        let Some(canonical_id) = path.claim_id() else {
            return Err(ClaimsError::InvalidInput(
                ClaimsInvalidReason::InvalidClaimPath,
            ));
        };
        if ancestors.contains(&canonical_id) {
            return Err(ClaimsError::InvalidInput(
                ClaimsInvalidReason::ParentChildClaimPathConflict,
            ));
        }
    }
    Ok(())
}

/// Validate a single claim definition.
pub fn validate_claim_definition(claim: &ClaimDefinition) -> Result<(), ClaimsError> {
    if claim.claim_id.len() > MAX_CLAIM_ID_BYTES {
        return Err(ClaimsError::InvalidInput(
            ClaimsInvalidReason::ClaimIdTooLong,
        ));
    }
    if !is_valid_claim_id(claim.claim_id.as_str()) {
        return Err(ClaimsError::InvalidInput(ClaimsInvalidReason::EmptyClaimId));
    }
    if matches!(claim.claim_type, ClaimType::Unspecified) {
        return Err(ClaimsError::InvalidInput(
            ClaimsInvalidReason::InvalidClaimType,
        ));
    }
    if claim.encoding.trim().is_empty() {
        return Err(ClaimsError::InvalidInput(
            ClaimsInvalidReason::EmptyEncoding,
        ));
    }
    if claim.disclosure.predicates.len() > MAX_DISCLOSURE_PREDICATES {
        return Err(ClaimsError::InvalidInput(
            ClaimsInvalidReason::TooManyPredicates,
        ));
    }
    if claim.disclosure.predicates.iter().any(|mode| {
        matches!(
            mode,
            DisclosureMode::Unspecified | DisclosureMode::Hidden | DisclosureMode::Reveal
        )
    }) {
        return Err(ClaimsError::InvalidInput(
            ClaimsInvalidReason::InvalidDisclosureMode,
        ));
    }

    Ok(())
}

/// Validate a credential claim payload against a registry.
pub fn validate_claim_payload(
    registry: &ClaimsRegistry,
    payload: &ClaimValue,
) -> Result<(), ClaimsError> {
    validate_registry(registry)?;
    let ClaimValue::Object(object) = payload else {
        return Err(ClaimsError::InvalidInput(
            ClaimsInvalidReason::ClaimPayloadRootNotObject,
        ));
    };

    let registry_ancestors = registry_ancestor_index(registry)?;
    validate_payload_object(registry, &registry_ancestors, "", object, 0)
}

/// Validate whether a claim path may be disclosed with the requested mode.
pub fn validate_disclosure(
    registry: &ClaimsRegistry,
    path: &str,
    mode: DisclosureMode,
) -> Result<(), ClaimsError> {
    validate_registry(registry)?;
    let claim_id = claim_id_from_path(path).ok_or(ClaimsError::InvalidInput(
        ClaimsInvalidReason::InvalidClaimPath,
    ))?;
    let def = registry
        .claims
        .get(claim_id)
        .ok_or(ClaimsError::UnknownClaim)?;

    match mode {
        DisclosureMode::Unspecified | DisclosureMode::Hidden => Err(ClaimsError::InvalidInput(
            ClaimsInvalidReason::InvalidDisclosureMode,
        )),
        DisclosureMode::Reveal if def.disclosure.allow_reveal => Ok(()),
        DisclosureMode::Reveal => Err(ClaimsError::DisclosureNotAllowed),
        predicate if def.disclosure.predicates.contains(&predicate) => Ok(()),
        _ => Err(ClaimsError::PredicateNotAllowed),
    }
}

/// Validate one normalized claim value against one claim definition.
pub fn validate_claim_value(
    definition: &ClaimDefinition,
    value: &ClaimValue,
) -> Result<(), ClaimsError> {
    match (definition.claim_type, value) {
        (ClaimType::String, ClaimValue::String(value)) => {
            crate::values::validate_string_value(value.as_str())
        }
        (ClaimType::Boolean, ClaimValue::Boolean(_)) => Ok(()),
        (ClaimType::Integer | ClaimType::SignedInteger, ClaimValue::Signed(_)) => Ok(()),
        // JSON normalization maps every non-negative integer to `Unsigned`, so
        // signed claim types accept it when it fits the signed range. The
        // commitment layer re-encodes it as the declared signed variant.
        (ClaimType::Integer | ClaimType::SignedInteger, ClaimValue::Unsigned(value)) => {
            i64::try_from(*value)
                .map(|_| ())
                .map_err(|_| ClaimsError::InvalidInput(ClaimsInvalidReason::ClaimValueTypeMismatch))
        }
        (ClaimType::UnsignedInteger, ClaimValue::Unsigned(_)) => Ok(()),
        (ClaimType::UnsignedInteger, ClaimValue::Signed(value)) => u64::try_from(*value)
            .map(|_| ())
            .map_err(|_| ClaimsError::InvalidInput(ClaimsInvalidReason::ClaimValueTypeMismatch)),
        (ClaimType::Number | ClaimType::Decimal, ClaimValue::Decimal(value)) => {
            crate::values::validate_decimal(value.as_str())
        }
        (ClaimType::Number, ClaimValue::Signed(_) | ClaimValue::Unsigned(_)) => Ok(()),
        (ClaimType::Bytes, ClaimValue::Bytes(value)) => {
            if value.len() > crate::values::MAX_CLAIM_BYTES_VALUE_BYTES {
                Err(ClaimsError::InvalidInput(
                    ClaimsInvalidReason::ClaimValueLimitExceeded,
                ))
            } else {
                Ok(())
            }
        }
        (ClaimType::Date, ClaimValue::Date(value)) => crate::values::validate_date(value.as_str()),
        (ClaimType::Date, ClaimValue::String(value)) => {
            crate::values::validate_date(value.as_str())
        }
        (ClaimType::DateTime, ClaimValue::DateTime(value)) => {
            crate::values::validate_date_time(value.as_str())
        }
        (ClaimType::DateTime, ClaimValue::String(value)) => {
            crate::values::validate_date_time(value.as_str())
        }
        (ClaimType::Null, ClaimValue::Null) => Ok(()),
        (ClaimType::Object, ClaimValue::Object(value)) => {
            if value.len() > crate::values::MAX_CLAIM_OBJECT_PROPERTIES {
                Err(ClaimsError::InvalidInput(
                    ClaimsInvalidReason::ClaimValueLimitExceeded,
                ))
            } else {
                Ok(())
            }
        }
        (ClaimType::Array, ClaimValue::Array(value)) => {
            if value.len() > crate::values::MAX_CLAIM_ARRAY_ITEMS {
                Err(ClaimsError::InvalidInput(
                    ClaimsInvalidReason::ClaimValueLimitExceeded,
                ))
            } else {
                Ok(())
            }
        }
        (ClaimType::Unspecified, _) => Err(ClaimsError::InvalidInput(
            ClaimsInvalidReason::InvalidClaimType,
        )),
        _ => Err(ClaimsError::InvalidInput(
            ClaimsInvalidReason::ClaimValueTypeMismatch,
        )),
    }
}

/// Canonical identifiers of every strict ancestor of a registered claim.
///
/// Built once per payload validation so each payload node is classified with a
/// set lookup instead of a scan over every registry path.
fn registry_ancestor_index(registry: &ClaimsRegistry) -> Result<BTreeSet<String>, ClaimsError> {
    let mut ancestors = BTreeSet::new();
    for claim in registry.claims.values() {
        let path = claim_path_for_id(claim.claim_id.as_str())?;
        ancestors.extend(path.strict_ancestor_claim_ids());
    }
    Ok(ancestors)
}

fn claim_path_for_id(claim_id: &str) -> Result<ClaimPath, ClaimsError> {
    let path_len =
        "/claims/"
            .len()
            .checked_add(claim_id.len())
            .ok_or(ClaimsError::InvalidInput(
                ClaimsInvalidReason::ClaimPathTooLong,
            ))?;
    let mut path = String::with_capacity(path_len);
    path.push_str("/claims/");
    path.push_str(claim_id);
    parse_claim_path(path.as_str())
}

fn validate_payload_object(
    registry: &ClaimsRegistry,
    registry_ancestors: &BTreeSet<String>,
    parent_id: &str,
    object: &BTreeMap<String, ClaimValue>,
    depth: usize,
) -> Result<(), ClaimsError> {
    if object.len() > crate::values::MAX_CLAIM_OBJECT_PROPERTIES {
        return Err(ClaimsError::InvalidInput(
            ClaimsInvalidReason::ClaimValueLimitExceeded,
        ));
    }
    let next_depth = depth.checked_add(1).ok_or(ClaimsError::InvalidInput(
        ClaimsInvalidReason::ClaimValueLimitExceeded,
    ))?;
    if next_depth > crate::values::MAX_CLAIM_VALUE_DEPTH {
        return Err(ClaimsError::InvalidInput(
            ClaimsInvalidReason::ClaimValueLimitExceeded,
        ));
    }

    for (key, value) in object {
        let escaped_key = escape_field_segment(key.as_str());
        let claim_id = append_claim_id(parent_id, escaped_key.as_str())?;
        validate_payload_value(
            registry,
            registry_ancestors,
            claim_id.as_str(),
            value,
            next_depth,
        )?;
    }

    Ok(())
}

fn validate_payload_array(
    registry: &ClaimsRegistry,
    registry_ancestors: &BTreeSet<String>,
    parent_id: &str,
    values: &[ClaimValue],
    depth: usize,
) -> Result<(), ClaimsError> {
    if values.len() > crate::values::MAX_CLAIM_ARRAY_ITEMS {
        return Err(ClaimsError::InvalidInput(
            ClaimsInvalidReason::ClaimValueLimitExceeded,
        ));
    }
    let next_depth = depth.checked_add(1).ok_or(ClaimsError::InvalidInput(
        ClaimsInvalidReason::ClaimValueLimitExceeded,
    ))?;
    if next_depth > crate::values::MAX_CLAIM_VALUE_DEPTH {
        return Err(ClaimsError::InvalidInput(
            ClaimsInvalidReason::ClaimValueLimitExceeded,
        ));
    }

    for (index, value) in values.iter().enumerate() {
        let index = u32::try_from(index)
            .map_err(|_| ClaimsError::InvalidInput(ClaimsInvalidReason::ClaimValueLimitExceeded))?;
        let index_segment = index.to_string();
        let claim_id = append_claim_id(parent_id, index_segment.as_str())?;
        validate_payload_value(
            registry,
            registry_ancestors,
            claim_id.as_str(),
            value,
            next_depth,
        )?;
    }

    Ok(())
}

fn validate_payload_value(
    registry: &ClaimsRegistry,
    registry_ancestors: &BTreeSet<String>,
    claim_id: &str,
    value: &ClaimValue,
    depth: usize,
) -> Result<(), ClaimsError> {
    validate_value_resource_limits(value, depth)?;
    let path = claim_path_for_id(claim_id)?;
    if let Some(definition) = registry.claims.get(claim_id) {
        return validate_claim_value(definition, value);
    }

    let Some(canonical_id) = path.claim_id() else {
        return Err(ClaimsError::UnknownClaim);
    };
    if !registry_ancestors.contains(&canonical_id) {
        return Err(ClaimsError::UnknownClaim);
    }

    match value {
        ClaimValue::Object(object) => {
            validate_payload_object(registry, registry_ancestors, claim_id, object, depth)
        }
        ClaimValue::Array(values) => {
            validate_payload_array(registry, registry_ancestors, claim_id, values, depth)
        }
        ClaimValue::Null
        | ClaimValue::Boolean(_)
        | ClaimValue::String(_)
        | ClaimValue::Signed(_)
        | ClaimValue::Unsigned(_)
        | ClaimValue::Decimal(_)
        | ClaimValue::Bytes(_)
        | ClaimValue::Date(_)
        | ClaimValue::DateTime(_) => Err(ClaimsError::UnknownClaim),
    }
}

fn validate_value_resource_limits(value: &ClaimValue, depth: usize) -> Result<(), ClaimsError> {
    if depth > crate::values::MAX_CLAIM_VALUE_DEPTH {
        return Err(ClaimsError::InvalidInput(
            ClaimsInvalidReason::ClaimValueLimitExceeded,
        ));
    }
    let next_depth = depth.checked_add(1).ok_or(ClaimsError::InvalidInput(
        ClaimsInvalidReason::ClaimValueLimitExceeded,
    ))?;
    match value {
        ClaimValue::String(value) => crate::values::validate_string_value(value.as_str()),
        ClaimValue::Bytes(value) if value.len() > crate::values::MAX_CLAIM_BYTES_VALUE_BYTES => {
            Err(ClaimsError::InvalidInput(
                ClaimsInvalidReason::ClaimValueLimitExceeded,
            ))
        }
        ClaimValue::Array(values) => {
            if values.len() > crate::values::MAX_CLAIM_ARRAY_ITEMS {
                return Err(ClaimsError::InvalidInput(
                    ClaimsInvalidReason::ClaimValueLimitExceeded,
                ));
            }
            for value in values {
                validate_value_resource_limits(value, next_depth)?;
            }
            Ok(())
        }
        ClaimValue::Object(values) => {
            if values.len() > crate::values::MAX_CLAIM_OBJECT_PROPERTIES {
                return Err(ClaimsError::InvalidInput(
                    ClaimsInvalidReason::ClaimValueLimitExceeded,
                ));
            }
            for (key, value) in values {
                crate::values::validate_string_value(key.as_str())?;
                validate_value_resource_limits(value, next_depth)?;
            }
            Ok(())
        }
        ClaimValue::Null
        | ClaimValue::Boolean(_)
        | ClaimValue::Signed(_)
        | ClaimValue::Unsigned(_)
        | ClaimValue::Decimal(_)
        | ClaimValue::Bytes(_)
        | ClaimValue::Date(_)
        | ClaimValue::DateTime(_) => Ok(()),
    }
}

fn append_claim_id(parent_id: &str, segment: &str) -> Result<String, ClaimsError> {
    if parent_id.is_empty() {
        return Ok(segment.to_owned());
    }
    let with_separator = parent_id
        .len()
        .checked_add(1)
        .ok_or(ClaimsError::InvalidInput(
            ClaimsInvalidReason::ClaimPathTooLong,
        ))?;
    let capacity = with_separator
        .checked_add(segment.len())
        .ok_or(ClaimsError::InvalidInput(
            ClaimsInvalidReason::ClaimPathTooLong,
        ))?;
    let mut out = String::with_capacity(capacity);
    out.push_str(parent_id);
    out.push('/');
    out.push_str(segment);
    Ok(out)
}
