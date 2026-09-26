// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::collections::{HashMap, HashSet};

use reallyme_codec::cbor::CborValue;
use reallyme_codec::multikey::parse_multikey;

use crate::canonical::cbor_to_json_value;
use crate::validate::diagnostic::{DidValidationCode, DidValidationIssue, DidValidationLocation};
use reallyme_did_types::DIDDocument;

/// Result of validating JSON projection fields against canonical core content.
#[derive(Debug)]
pub struct ProjectionValidationResult {
    /// Whether the JSON projection matches the canonical core.
    pub ok: bool,

    /// Machine-readable validation issues collected for callers and tests.
    pub errors: Vec<DidValidationIssue>,
}

fn projection_issue(location: DidValidationLocation) -> DidValidationIssue {
    DidValidationIssue::new(DidValidationCode::CoreProjectionMismatch, location)
}

/// Validate JSON and core projection consistency.
pub fn validate_projection(doc: &DIDDocument, core: &CborValue) -> ProjectionValidationResult {
    let mut errors = Vec::new();

    // ---------------------------------------------------------------------
    // 0. keyHistory
    // ---------------------------------------------------------------------
    let kh = &doc.key_history;

    match u64::try_from(kh.len())
        .ok()
        .and_then(|len| len.checked_add(1))
    {
        Some(expected_sequence) if doc.sequence == expected_sequence => {}
        _ => errors.push(projection_issue(DidValidationLocation::KeyHistory)),
    }

    if doc.sequence == 1 {
        if doc.prev.is_some() {
            errors.push(projection_issue(DidValidationLocation::Core));
        }
        match (map_get(core, "nonce"), doc.nonce.as_deref()) {
            (Some(CborValue::Bytes(core_nonce)), Some(doc_nonce)) => {
                match reallyme_codec::base64url::base64url_to_bytes(doc_nonce) {
                    Ok(bytes) if bytes == *core_nonce => {}
                    Ok(_) => errors.push(projection_issue(DidValidationLocation::Nonce)),
                    Err(_) => errors.push(DidValidationIssue::new(
                        DidValidationCode::CoreCborEncodingInvalid,
                        DidValidationLocation::Nonce,
                    )),
                }
            }
            _ => errors.push(projection_issue(DidValidationLocation::Nonce)),
        }
        if !kh.is_empty() {
            errors.push(projection_issue(DidValidationLocation::KeyHistory));
        }
    } else {
        match (&doc.prev, kh.last()) {
            (Some(p), Some(last)) if p == last => {}
            _ => errors.push(projection_issue(DidValidationLocation::KeyHistory)),
        }
    }

    // ---------------------------------------------------------------------
    // 1. verificationMethod ↔ core.controllerKeys (exact field equality)
    // ---------------------------------------------------------------------
    // The JSON verification methods are an unsigned projection. Every field
    // that consumers rely on must be bound to the signed core, not just the id.
    let core_vms = map_get_array(core, "controllerKeys");
    let mut core_vm_by_id: HashMap<&str, &CborValue> = HashMap::with_capacity(core_vms.len());
    for vm in &core_vms {
        match map_get_string(vm, "id") {
            Some(id) => {
                if core_vm_by_id.insert(id, vm).is_some() {
                    errors.push(projection_issue(DidValidationLocation::VerificationMethod));
                }
            }
            None => errors.push(projection_issue(DidValidationLocation::VerificationMethod)),
        }
    }

    if core_vms.len() != doc.verification_method.len() {
        errors.push(projection_issue(DidValidationLocation::VerificationMethod));
    }

    let mut matched_doc_ids: HashSet<&str> = HashSet::with_capacity(doc.verification_method.len());
    for vm in &doc.verification_method {
        if !matched_doc_ids.insert(vm.id.as_str()) {
            errors.push(projection_issue(DidValidationLocation::VerificationMethod));
            continue;
        }
        let Some(core_vm) = core_vm_by_id.get(vm.id.as_str()) else {
            errors.push(projection_issue(DidValidationLocation::VerificationMethod));
            continue;
        };
        if map_get_string(core_vm, "type") != Some(vm.vm_type.as_str())
            || map_get_string(core_vm, "algorithm") != vm.algorithm.as_deref()
            || map_get_string(core_vm, "publicKeyMultibase")
                != Some(vm.public_key_multibase.as_str())
            || vm.controller != doc.id
        {
            errors.push(projection_issue(DidValidationLocation::VerificationMethod));
        }
    }

    // Algorithm + multikey consistency
    for vm in &doc.verification_method {
        match parse_multikey(&vm.public_key_multibase) {
            Ok(parsed) => {
                if let Some(alg) = &vm.algorithm {
                    if alg != parsed.alg {
                        errors.push(projection_issue(DidValidationLocation::VerificationMethod));
                    }
                }
            }
            Err(_) => {
                errors.push(DidValidationIssue::new(
                    DidValidationCode::VerificationMethodInvalid,
                    DidValidationLocation::VerificationMethod,
                ));
            }
        }
    }

    // ---------------------------------------------------------------------
    // 2. services (existence symmetry)
    // ---------------------------------------------------------------------
    let core_services = map_get_array(core, "services");
    let core_service_ids: HashSet<&str> = core_services
        .iter()
        .filter_map(|service| map_get_string(service, "id"))
        .collect();
    let doc_service_by_id: HashMap<&str, &reallyme_did_types::Service> = doc
        .service
        .iter()
        .map(|service| (service.id.as_str(), service))
        .collect();

    if core_service_ids.len() != core_services.len() || doc_service_by_id.len() != doc.service.len()
    {
        errors.push(projection_issue(DidValidationLocation::Service));
    }

    for id in &core_service_ids {
        if !doc_service_by_id.contains_key(id) {
            errors.push(projection_issue(DidValidationLocation::Service));
        }
    }

    for id in doc_service_by_id.keys() {
        if !core_service_ids.contains(id) {
            errors.push(projection_issue(DidValidationLocation::Service));
        }
    }

    for service_value in core_services {
        let Some(core_id) = map_get_string(service_value, "id") else {
            continue;
        };
        let Some(doc_service) = doc_service_by_id.get(core_id) else {
            continue;
        };

        if map_get_string(service_value, "type") != Some(doc_service.service_type.as_str()) {
            errors.push(projection_issue(DidValidationLocation::Service));
        }

        match map_get(service_value, "serviceEndpoint") {
            Some(endpoint)
                if cbor_to_json_value(endpoint)
                    .is_ok_and(|value| value == doc_service.service_endpoint) => {}
            Some(_) => errors.push(projection_issue(DidValidationLocation::Service)),
            None => errors.push(projection_issue(DidValidationLocation::Service)),
        }
    }

    // ---------------------------------------------------------------------
    // 3. updatePolicy projection
    // ---------------------------------------------------------------------
    if let Some(core_up) = map_get(core, "updatePolicy") {
        match &doc.update_policy {
            Some(doc_up) => {
                let core_allowed = map_get_string_array(core_up, "allowedVerificationMethods");

                if doc_up.allowed_verification_methods != core_allowed {
                    errors.push(projection_issue(DidValidationLocation::UpdatePolicy));
                }

                if doc.capability_invocation != core_allowed {
                    errors.push(projection_issue(DidValidationLocation::Relationship));
                }

                let core_threshold = map_get_u64(core_up, "threshold");
                if doc_up.threshold != core_threshold {
                    errors.push(projection_issue(DidValidationLocation::UpdatePolicy));
                }
            }

            None => {
                errors.push(projection_issue(DidValidationLocation::UpdatePolicy));
                // IMPORTANT: do NOT return
            }
        }
    }

    // ---------------------------------------------------------------------
    // 4. Relationship projection (TS check() equivalents)
    // ---------------------------------------------------------------------
    check_rel(
        "authentication",
        "authenticationKeys",
        &doc.authentication,
        core,
        &mut errors,
    );

    check_rel(
        "assertionMethod",
        "assertionKeys",
        &doc.assertion_method,
        core,
        &mut errors,
    );

    check_rel(
        "keyAgreement",
        "keyAgreementKeys",
        &doc.key_agreement,
        core,
        &mut errors,
    );

    finish(errors)
}

// -----------------------------------------------------------------------------
// Helpers (CBOR map-safe)
// -----------------------------------------------------------------------------

fn finish(errors: Vec<DidValidationIssue>) -> ProjectionValidationResult {
    ProjectionValidationResult {
        ok: errors.is_empty(),
        errors,
    }
}
fn map_get<'a>(v: &'a CborValue, key: &str) -> Option<&'a CborValue> {
    match v {
        CborValue::Map(m) => m
            .iter()
            .find_map(|(k, v)| if k == key { Some(v) } else { None }),
        _ => None,
    }
}

fn map_get_string<'a>(v: &'a CborValue, key: &str) -> Option<&'a str> {
    match map_get(v, key) {
        Some(CborValue::String(s)) => Some(s),
        _ => None,
    }
}

fn map_get_array<'a>(v: &'a CborValue, key: &str) -> Vec<&'a CborValue> {
    match map_get(v, key) {
        Some(CborValue::Array(a)) => a.iter().collect(),
        _ => Vec::new(),
    }
}

fn map_get_string_array(v: &CborValue, key: &str) -> Vec<String> {
    match map_get(v, key) {
        Some(CborValue::Array(a)) => a
            .iter()
            .filter_map(|x| match x {
                CborValue::String(s) => Some(s.clone()),
                _ => None,
            })
            .collect(),
        _ => Vec::new(),
    }
}

fn check_rel(
    _name: &str,
    core_field: &str,
    doc_list: &[String],
    core: &CborValue,
    errors: &mut Vec<DidValidationIssue>,
) {
    let c_list = map_get_string_array(core, core_field);
    let core_set: HashSet<&str> = c_list.iter().map(String::as_str).collect();
    let doc_set: HashSet<&str> = doc_list.iter().map(String::as_str).collect();

    if core_set.len() != c_list.len() || doc_set.len() != doc_list.len() || core_set != doc_set {
        errors.push(projection_issue(DidValidationLocation::Relationship));
    }
}
fn map_get_u64(value: &CborValue, key: &str) -> Option<u64> {
    match map_get(value, key) {
        Some(CborValue::Int(n)) if *n >= 0 => u64::try_from(*n).ok(),
        _ => None,
    }
}
