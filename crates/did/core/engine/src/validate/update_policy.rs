// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_did_types::DIDDocument;
use std::collections::HashSet;

use crate::validate::diagnostic::{DidValidationCode, DidValidationIssue, DidValidationLocation};

/// Result of semantic update-policy validation.
#[derive(Debug, Clone)]
pub struct UpdatePolicyValidationResult {
    /// Whether the update policy is present and satisfiable.
    pub ok: bool,

    /// Machine-readable validation issues collected for callers and tests.
    pub errors: Vec<DidValidationIssue>,
}

fn update_policy_issue() -> DidValidationIssue {
    DidValidationIssue::new(
        DidValidationCode::UpdatePolicyInvalid,
        DidValidationLocation::UpdatePolicy,
    )
}

//Helper
fn normalize_vm_id(did: &str, id: &str) -> String {
    if id.starts_with('#') {
        format!("{did}{id}")
    } else {
        id.to_string()
    }
}

/// Semantic validation of updatePolicy (no crypto).
///
/// Mirrors TS validateUpdatePolicy exactly.
pub fn validate_update_policy(doc: &DIDDocument) -> UpdatePolicyValidationResult {
    let mut errors = Vec::new();
    let terminal = is_terminal_deactivation_shape(doc);

    let up = match &doc.update_policy {
        Some(up) => up,
        None => {
            errors.push(update_policy_issue());
            return UpdatePolicyValidationResult { ok: false, errors };
        }
    };

    // Normalize allowed VM ids
    let allowed: Vec<String> = up
        .allowed_verification_methods
        .iter()
        .map(|id| normalize_vm_id(&doc.id, id))
        .collect();

    // --------------------------------------------------
    // 1. allowed must not be empty
    // --------------------------------------------------
    if allowed.is_empty() && !terminal {
        errors.push(update_policy_issue());
    }

    if allowed.len() != allowed.iter().collect::<HashSet<_>>().len() {
        errors.push(update_policy_issue());
    }

    // --------------------------------------------------
    // 2. allowed must reference real VM IDs
    // --------------------------------------------------
    let vm_ids: HashSet<String> = doc
        .verification_method
        .iter()
        .map(|v| normalize_vm_id(&doc.id, &v.id))
        .collect();

    for vm_id in &allowed {
        if !vm_ids.contains(vm_id) {
            errors.push(update_policy_issue());
        }
    }

    // --------------------------------------------------
    // 3. threshold must be satisfiable by distinct allowed methods
    // --------------------------------------------------
    if let Some(threshold) = up.threshold {
        let threshold_usize = match usize::try_from(threshold) {
            Ok(value) => value,
            Err(_) => {
                errors.push(update_policy_issue());
                return UpdatePolicyValidationResult { ok: false, errors };
            }
        };

        if threshold_usize == 0 || threshold_usize > allowed.len() {
            errors.push(update_policy_issue());
        }
    }

    UpdatePolicyValidationResult {
        ok: errors.is_empty(),
        errors,
    }
}

fn is_terminal_deactivation_shape(doc: &DIDDocument) -> bool {
    let Some(update_policy) = &doc.update_policy else {
        return false;
    };

    doc.sequence > 1
        && doc.prev.is_some()
        && doc.nonce.is_none()
        && doc.verification_method.is_empty()
        && doc.authentication.is_empty()
        && doc.assertion_method.is_empty()
        && doc.capability_invocation.is_empty()
        && doc.key_agreement.is_empty()
        && doc.service.is_empty()
        && update_policy.allowed_verification_methods.is_empty()
        && update_policy.threshold.is_none()
}
