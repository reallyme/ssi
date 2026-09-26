// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use identity_core_primitives::algorithm_map::alg_str_to_alg;
use reallyme_did_types::{DIDDocument, VerificationMethod};
use std::collections::{HashMap, HashSet};

use crate::signing::attestation_crypto_algorithm;

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

    // Policy references are compared exactly, in the same fragment-relative
    // form used by verification method ids and attestation `vm` references.
    let allowed = &up.allowed_verification_methods;

    // --------------------------------------------------
    // 1. allowed must not be empty
    // --------------------------------------------------
    if allowed.is_empty() && !terminal {
        errors.push(update_policy_issue());
    }

    if allowed.len() != allowed.iter().collect::<HashSet<_>>().len()
        || !allowed.iter().all(|id| id.starts_with('#'))
    {
        errors.push(update_policy_issue());
    }

    // --------------------------------------------------
    // 2. allowed must reference real VM IDs
    // --------------------------------------------------
    let vm_by_id: HashMap<&str, &VerificationMethod> = doc
        .verification_method
        .iter()
        .map(|vm| (vm.id.as_str(), vm))
        .collect();

    for vm_id in allowed {
        // Allowed methods must exist and use a core attestation algorithm.
        let attestation_capable = vm_by_id
            .get(vm_id.as_str())
            .and_then(|vm| vm.algorithm.as_deref())
            .and_then(|alg| alg_str_to_alg(alg).ok())
            .and_then(attestation_crypto_algorithm)
            .is_some();
        if !attestation_capable {
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
