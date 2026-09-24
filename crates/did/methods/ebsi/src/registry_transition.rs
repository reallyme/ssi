// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Exact public-state transitions for authenticated EBSI registry writes.

use std::collections::BTreeSet;

use serde_json::{Map, Value};

use crate::{DidEbsiDocument, DidEbsiError, DidEbsiErrorReason, DidEbsiRegistryOperation};

const PROTECTED_UPDATE_PROPERTIES: [&str; 8] = [
    "controller",
    "verificationMethod",
    "authentication",
    "assertionMethod",
    "keyAgreement",
    "capabilityInvocation",
    "capabilityDelegation",
    "id",
];
const RELATIONSHIP_PROPERTIES: [&str; 5] = [
    "authentication",
    "assertionMethod",
    "keyAgreement",
    "capabilityInvocation",
    "capabilityDelegation",
];

pub(crate) fn validate_transition(
    operation: DidEbsiRegistryOperation,
    current: &DidEbsiDocument,
    proposed: &DidEbsiDocument,
    target: Option<&str>,
) -> Result<(), DidEbsiError> {
    if current.id() != proposed.id() {
        return Err(DidEbsiError::new(
            DidEbsiErrorReason::DocumentIdentifierMismatch,
        ));
    }
    let valid = match operation {
        DidEbsiRegistryOperation::RegisterDocument => false,
        DidEbsiRegistryOperation::UpdateDocument => PROTECTED_UPDATE_PROPERTIES
            .iter()
            .all(|name| property_equal(current, proposed, name)),
        DidEbsiRegistryOperation::AddController => {
            exact_set_change(current, proposed, "controller", target, true)
                && authority_properties_equal(current, proposed, "controller")
        }
        DidEbsiRegistryOperation::RevokeController => {
            exact_set_change(current, proposed, "controller", target, false)
                && authority_properties_equal(current, proposed, "controller")
        }
        DidEbsiRegistryOperation::AddVerificationMethod => {
            exact_method_change(current, proposed, target, true)
                && authority_properties_equal(current, proposed, "verificationMethod")
        }
        DidEbsiRegistryOperation::AddVerificationRelationship => {
            exact_relationship_change(current, proposed, target, true)
        }
        DidEbsiRegistryOperation::RevokeVerificationRelationship => {
            exact_relationship_change(current, proposed, target, false)
        }
        DidEbsiRegistryOperation::RotateVerificationMethod => {
            rotated_exact_method(current, proposed, target)
        }
        DidEbsiRegistryOperation::ExpireVerificationMethod
        | DidEbsiRegistryOperation::RevokeVerificationMethod => {
            exact_method_change(current, proposed, target, false)
                && relationships_remove_target(current, proposed, target)
                && property_equal(current, proposed, "controller")
        }
        DidEbsiRegistryOperation::DeactivateKeys => proposed.is_effectively_deactivated(),
    };
    if valid {
        Ok(())
    } else {
        Err(DidEbsiError::new(DidEbsiErrorReason::InvalidDocument))
    }
}

fn property_equal(current: &DidEbsiDocument, proposed: &DidEbsiDocument, name: &str) -> bool {
    current.value.get(name) == proposed.value.get(name)
}

fn authority_properties_equal(
    current: &DidEbsiDocument,
    proposed: &DidEbsiDocument,
    except: &str,
) -> bool {
    PROTECTED_UPDATE_PROPERTIES
        .iter()
        .filter(|name| **name != except)
        .all(|name| property_equal(current, proposed, name))
}

fn exact_set_change(
    current: &DidEbsiDocument,
    proposed: &DidEbsiDocument,
    property: &str,
    target: Option<&str>,
    added: bool,
) -> bool {
    let Some(target) = target else {
        return false;
    };
    let Some(before) = string_set(current.value.get(property)) else {
        return false;
    };
    let Some(after) = string_set(proposed.value.get(property)) else {
        return false;
    };
    set_change_matches(&before, &after, target, added)
}

fn exact_method_change(
    current: &DidEbsiDocument,
    proposed: &DidEbsiDocument,
    target: Option<&str>,
    added: bool,
) -> bool {
    let Some(target) = target else {
        return false;
    };
    let Some(before) = method_ids(&current.value) else {
        return false;
    };
    let Some(after) = method_ids(&proposed.value) else {
        return false;
    };
    set_change_matches(&before, &after, target, added)
}

fn set_change_matches(
    before: &BTreeSet<&str>,
    after: &BTreeSet<&str>,
    target: &str,
    added: bool,
) -> bool {
    let Some(expected_larger_len) = (if added {
        before.len().checked_add(1)
    } else {
        after.len().checked_add(1)
    }) else {
        return false;
    };
    if added {
        !before.contains(target)
            && after.contains(target)
            && after.len() == expected_larger_len
            && before.is_subset(after)
    } else {
        before.contains(target)
            && !after.contains(target)
            && before.len() == expected_larger_len
            && after.is_subset(before)
    }
}

fn string_set(value: Option<&Value>) -> Option<BTreeSet<&str>> {
    match value? {
        Value::String(value) => Some(BTreeSet::from([value.as_str()])),
        Value::Array(values) => values.iter().map(Value::as_str).collect(),
        _ => None,
    }
}

fn method_ids(value: &Value) -> Option<BTreeSet<&str>> {
    value
        .get("verificationMethod")?
        .as_array()?
        .iter()
        .map(|method| method.as_object()?.get("id")?.as_str())
        .collect()
}

fn rotated_exact_method(
    current: &DidEbsiDocument,
    proposed: &DidEbsiDocument,
    target: Option<&str>,
) -> bool {
    let Some(target) = target else {
        return false;
    };
    if method_ids(&current.value) != method_ids(&proposed.value)
        || !authority_properties_equal(current, proposed, "verificationMethod")
    {
        return false;
    }
    let Some(before) = current.verification_method(target) else {
        return false;
    };
    let Some(after) = proposed.verification_method(target) else {
        return false;
    };
    method_identity_equal(before, after) && before.get("publicKeyJwk") != after.get("publicKeyJwk")
}

fn method_identity_equal(before: &Map<String, Value>, after: &Map<String, Value>) -> bool {
    ["id", "type", "controller"]
        .iter()
        .all(|name| before.get(*name) == after.get(*name))
}

fn exact_relationship_change(
    current: &DidEbsiDocument,
    proposed: &DidEbsiDocument,
    target: Option<&str>,
    added: bool,
) -> bool {
    let Some(target) = target else {
        return false;
    };
    if !property_equal(current, proposed, "controller")
        || !property_equal(current, proposed, "verificationMethod")
    {
        return false;
    }
    let changed = RELATIONSHIP_PROPERTIES
        .iter()
        .filter(|name| !property_equal(current, proposed, name))
        .copied()
        .collect::<Vec<_>>();
    changed.len() == 1 && exact_set_change(current, proposed, changed[0], Some(target), added)
}

fn relationships_remove_target(
    current: &DidEbsiDocument,
    proposed: &DidEbsiDocument,
    target: Option<&str>,
) -> bool {
    let Some(target) = target else {
        return false;
    };
    RELATIONSHIP_PROPERTIES.iter().all(|name| {
        let before = string_set(current.value.get(*name)).unwrap_or_default();
        let after = string_set(proposed.value.get(*name)).unwrap_or_default();
        !after.contains(target)
            && after
                == before
                    .into_iter()
                    .filter(|identifier| *identifier != target)
                    .collect()
    })
}
