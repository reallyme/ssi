// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_did_types::DIDDocument;

use identity_core_primitives::algorithm_map::alg_str_to_alg;
use identity_core_primitives::Algorithm;

use crate::validate::diagnostic::{DidValidationCode, DidValidationIssue, DidValidationLocation};

/// Result of service validation.
#[derive(Debug, Clone)]
pub struct ServiceValidationResult {
    /// Whether all service entries are structurally valid.
    pub ok: bool,

    /// Machine-readable validation issues collected for callers and tests.
    pub errors: Vec<DidValidationIssue>,
}

const MAX_DIAGNOSTIC_INDEX: u32 = u32::MAX;
const MESSAGING_SERVICE_TYPE: &str = "MessagingService";
const MESSAGING_SERVICE_URI_FIELD: &str = "uri";
const MESSAGING_SERVICE_PRE_KEYS_FIELD: &str = "preKeys";

fn service_issue(index: usize) -> DidValidationIssue {
    let index = match u32::try_from(index) {
        Ok(value) => value,
        Err(_) => MAX_DIAGNOSTIC_INDEX,
    };
    DidValidationIssue::indexed(
        DidValidationCode::ServiceInvalid,
        DidValidationLocation::Service,
        index,
    )
}

/// Validate `service[]` entries in a did:me DID Document.
///
/// Mirrors TS `validateServices` exactly:
/// - service ids must be unique
/// - type must be string
/// - serviceEndpoint must exist and be string | object | array
/// - MessagingService endpoints must name hybrid key-agreement pre-keys
pub fn validate_services(doc: &DIDDocument) -> ServiceValidationResult {
    let mut errors = Vec::new();
    let services = &doc.service;

    // --------------------------------------------------
    // 1. Unique service IDs
    // --------------------------------------------------
    let mut seen = std::collections::HashSet::new();
    for (index, s) in services.iter().enumerate() {
        if !seen.insert(&s.id) {
            errors.push(service_issue(index));
        }
    }

    // --------------------------------------------------
    // 2. Validate service structure
    // --------------------------------------------------
    for (index, s) in services.iter().enumerate() {
        if s.service_type.is_empty() {
            errors.push(service_issue(index));
        }

        // serviceEndpoint is required
        let ep = &s.service_endpoint;
        if ep.is_null() {
            errors.push(service_issue(index));
            continue;
        }

        // Must be string OR array OR object
        let valid = ep.is_string() || ep.is_array() || ep.is_object();
        if !valid {
            errors.push(service_issue(index));
        }

        if s.service_type == MESSAGING_SERVICE_TYPE {
            validate_messaging_service(doc, index, &mut errors);
        }
    }

    ServiceValidationResult {
        ok: errors.is_empty(),
        errors,
    }
}

fn validate_messaging_service(
    doc: &DIDDocument,
    service_index: usize,
    errors: &mut Vec<DidValidationIssue>,
) {
    let service = match doc.service.get(service_index) {
        Some(service) => service,
        None => {
            errors.push(service_issue(service_index));
            return;
        }
    };

    let endpoint = match service.service_endpoint.as_object() {
        Some(endpoint) => endpoint,
        None => {
            errors.push(service_issue(service_index));
            return;
        }
    };

    match endpoint
        .get(MESSAGING_SERVICE_URI_FIELD)
        .and_then(|value| value.as_str())
    {
        Some(uri) if !uri.is_empty() => {}
        _ => errors.push(service_issue(service_index)),
    }

    let pre_keys = match endpoint
        .get(MESSAGING_SERVICE_PRE_KEYS_FIELD)
        .and_then(|value| value.as_array())
    {
        Some(pre_keys) if !pre_keys.is_empty() => pre_keys,
        _ => {
            errors.push(service_issue(service_index));
            return;
        }
    };

    let mut has_x25519 = false;
    let mut has_ml_kem = false;
    let mut seen_pre_keys = std::collections::HashSet::new();

    for pre_key in pre_keys {
        let Some(pre_key_id) = pre_key.as_str().filter(|value| !value.is_empty()) else {
            errors.push(service_issue(service_index));
            continue;
        };

        if !seen_pre_keys.insert(pre_key_id) {
            errors.push(service_issue(service_index));
            continue;
        }

        if !doc
            .key_agreement
            .iter()
            .any(|key_agreement_id| key_agreement_id == pre_key_id)
        {
            errors.push(service_issue(service_index));
            continue;
        }

        let Some(vm) = doc
            .verification_method
            .iter()
            .find(|vm| vm.id == pre_key_id)
        else {
            errors.push(service_issue(service_index));
            continue;
        };

        let Some(algorithm) = vm.algorithm.as_deref() else {
            errors.push(service_issue(service_index));
            continue;
        };

        match alg_str_to_alg(algorithm) {
            Ok(Algorithm::X25519) => has_x25519 = true,
            Ok(Algorithm::MlKem768 | Algorithm::MlKem1024) => has_ml_kem = true,
            Ok(
                Algorithm::Ed25519 | Algorithm::Secp256k1 | Algorithm::P256 | Algorithm::MlDsa87,
            )
            | Err(_) => errors.push(service_issue(service_index)),
        }
    }

    // Messaging pre-key discovery is intentionally hybrid-only: the signed core
    // must publish both a classical X25519 pre-key and a post-quantum ML-KEM
    // pre-key so senders never bootstrap new sessions from a classical-only
    // harvest-now-decrypt-later exposure point.
    if !has_x25519 || !has_ml_kem {
        errors.push(service_issue(service_index));
    }
}
