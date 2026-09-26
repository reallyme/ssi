// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0
use std::collections::HashSet;

use reallyme_codec::base64url::base64url_to_bytes;
use reallyme_did_types::{Controller, DIDDocument};

use crate::validate::diagnostic::{DidValidationCode, DidValidationIssue, DidValidationLocation};
use crate::validate::limits::{
    MAX_ALSO_KNOWN_AS, MAX_ATTESTATIONS, MAX_CONTEXT_ENTRIES, MAX_CONTROLLERS,
    MAX_CORE_CBOR_ENCODED_BYTES, MAX_DOMAIN_VERIFICATIONS, MAX_KEY_HISTORY_ENTRIES,
    MAX_RELATIONSHIP_REFERENCES, MAX_SERVICES, MAX_VERIFICATION_METHODS,
};

/// Result of top-level did:me DID Document structure validation.
#[derive(Debug, Clone)]
pub struct StructureValidationResult {
    /// Whether the document satisfies required structural checks.
    pub ok: bool,

    /// Machine-readable validation issues collected for callers and tests.
    pub errors: Vec<DidValidationIssue>,
}

const MAX_DIAGNOSTIC_INDEX: u32 = u32::MAX;

fn issue(code: DidValidationCode, location: DidValidationLocation) -> DidValidationIssue {
    DidValidationIssue::new(code, location)
}

fn indexed_issue(
    code: DidValidationCode,
    location: DidValidationLocation,
    index: usize,
) -> DidValidationIssue {
    let index = match u32::try_from(index) {
        Ok(value) => value,
        Err(_) => MAX_DIAGNOSTIC_INDEX,
    };
    DidValidationIssue::indexed(code, location, index)
}

fn is_did_me(s: &str) -> bool {
    s.starts_with("did:me:")
}

/// Validate top-level did:me DID Document structure before deeper semantic checks.
pub fn validate_did_me_structure(doc: &DIDDocument) -> StructureValidationResult {
    if exceeds_resource_limits(doc) {
        return StructureValidationResult {
            ok: false,
            errors: vec![issue(
                DidValidationCode::ResourceLimitExceeded,
                DidValidationLocation::Document,
            )],
        };
    }

    let mut errors = Vec::new();
    let terminal = is_terminal_deactivation_shape(doc);

    // ---------------------------------------------------------------------
    //
    // ---------------------------------------------------------------------
    let canonical_context = [
        "https://www.w3.org/ns/did/v1",
        "https://w3id.org/security/multikey/v1",
        "https://did-me.org/ns/did-me/v1",
    ];

    if doc.context.len() < canonical_context.len() {
        errors.push(issue(
            DidValidationCode::ContextInvalid,
            DidValidationLocation::Context,
        ));
    } else {
        for (idx, expected) in canonical_context.iter().enumerate() {
            if doc.context.get(idx).map(|s| s.as_str()) != Some(*expected) {
                errors.push(issue(
                    DidValidationCode::ContextInvalid,
                    DidValidationLocation::Context,
                ));
                break;
            }
        }
    }

    // Best-effort guard: prevent duplicate context URLs.
    // Full JSON-LD term redefinition checks require context dereferencing and are enforced as a spec rule.
    let mut seen_contexts = HashSet::new();
    for ctx in &doc.context {
        if !seen_contexts.insert(ctx) {
            errors.push(issue(
                DidValidationCode::ContextInvalid,
                DidValidationLocation::Context,
            ));
            break;
        }
    }

    // ---------------------------------------------------------------------
    // id
    // ---------------------------------------------------------------------
    if !is_did_me(&doc.id) {
        errors.push(issue(
            DidValidationCode::IdentifierInvalid,
            DidValidationLocation::Id,
        ));
    }

    // ---------------------------------------------------------------------
    // controller
    // ---------------------------------------------------------------------
    match &doc.controller {
        Controller::Single(c) => {
            if !c.starts_with("did:me:") {
                errors.push(issue(
                    DidValidationCode::ControllerInvalid,
                    DidValidationLocation::Controller,
                ));
            }
        }
        Controller::Multiple(v) => {
            if v.is_empty() || !v.iter().all(|d| d.starts_with("did:me:")) {
                errors.push(issue(
                    DidValidationCode::ControllerInvalid,
                    DidValidationLocation::Controller,
                ));
            }
        }
    }

    // ---------------------------------------------------------------------
    // alsoKnownAs
    // ---------------------------------------------------------------------
    for aka in &doc.also_known_as {
        if aka.is_empty() {
            errors.push(issue(
                DidValidationCode::AlsoKnownAsInvalid,
                DidValidationLocation::AlsoKnownAs,
            ));
        }
    }

    // ---------------------------------------------------------------------
    // core state
    // ---------------------------------------------------------------------
    if doc.sequence < 1 {
        errors.push(issue(
            DidValidationCode::CoreStateInvalid,
            DidValidationLocation::Core,
        ));
    }

    if doc.current_core.is_empty() {
        errors.push(issue(
            DidValidationCode::CoreStateInvalid,
            DidValidationLocation::Core,
        ));
    }

    if doc.core_cbor.is_empty() {
        errors.push(issue(
            DidValidationCode::CoreCborEncodingInvalid,
            DidValidationLocation::Core,
        ));
    }

    // ---------------------------------------------------------------------
    // keyHistory
    // ---------------------------------------------------------------------
    let kh = &doc.key_history;

    if !kh.iter().all(|x| !x.is_empty()) {
        errors.push(issue(
            DidValidationCode::CoreStateInvalid,
            DidValidationLocation::KeyHistory,
        ));
    }

    if kh.len() != kh.iter().collect::<HashSet<_>>().len() {
        errors.push(issue(
            DidValidationCode::CoreStateInvalid,
            DidValidationLocation::KeyHistory,
        ));
    }

    if kh.contains(&doc.current_core) {
        errors.push(issue(
            DidValidationCode::CoreStateInvalid,
            DidValidationLocation::KeyHistory,
        ));
    }

    match u64::try_from(kh.len())
        .ok()
        .and_then(|len| len.checked_add(1))
    {
        Some(expected_sequence) if doc.sequence == expected_sequence => {}
        _ => errors.push(issue(
            DidValidationCode::CoreStateInvalid,
            DidValidationLocation::Core,
        )),
    }

    if doc.sequence == 1 {
        if doc.prev.is_some() {
            errors.push(issue(
                DidValidationCode::CoreStateInvalid,
                DidValidationLocation::Core,
            ));
        }
        match doc.nonce.as_deref() {
            Some(nonce) => match base64url_to_bytes(nonce) {
                Ok(bytes) if bytes.len() == 16 => {}
                Ok(_) => errors.push(issue(
                    DidValidationCode::CoreStateInvalid,
                    DidValidationLocation::Nonce,
                )),
                Err(_) => errors.push(issue(
                    DidValidationCode::CoreCborEncodingInvalid,
                    DidValidationLocation::Nonce,
                )),
            },
            None => errors.push(issue(
                DidValidationCode::CoreStateInvalid,
                DidValidationLocation::Nonce,
            )),
        }
        if !kh.is_empty() {
            errors.push(issue(
                DidValidationCode::CoreStateInvalid,
                DidValidationLocation::KeyHistory,
            ));
        }
    } else {
        if doc.nonce.is_some() {
            errors.push(issue(
                DidValidationCode::CoreStateInvalid,
                DidValidationLocation::Nonce,
            ));
        }
        match &doc.prev {
            Some(p) => {
                if kh.last() != Some(p) {
                    errors.push(issue(
                        DidValidationCode::CoreStateInvalid,
                        DidValidationLocation::Core,
                    ));
                }
            }
            None => errors.push(issue(
                DidValidationCode::CoreStateInvalid,
                DidValidationLocation::Core,
            )),
        }
    }

    // ---------------------------------------------------------------------
    // verificationMethod[]
    // ---------------------------------------------------------------------
    if doc.verification_method.is_empty() && !terminal {
        errors.push(issue(
            DidValidationCode::VerificationMethodInvalid,
            DidValidationLocation::VerificationMethod,
        ));
    }

    for (i, vm) in doc.verification_method.iter().enumerate() {
        if !vm.id.starts_with('#') {
            errors.push(indexed_issue(
                DidValidationCode::VerificationMethodInvalid,
                DidValidationLocation::VerificationMethod,
                i,
            ));
        }

        if !vm.controller.starts_with("did:") {
            errors.push(indexed_issue(
                DidValidationCode::VerificationMethodInvalid,
                DidValidationLocation::VerificationMethod,
                i,
            ));
        }

        if vm.vm_type != "Multikey" {
            errors.push(indexed_issue(
                DidValidationCode::VerificationMethodInvalid,
                DidValidationLocation::VerificationMethod,
                i,
            ));
        }

        if vm.public_key_multibase.is_empty() {
            errors.push(indexed_issue(
                DidValidationCode::VerificationMethodInvalid,
                DidValidationLocation::VerificationMethod,
                i,
            ));
        }

        if vm.algorithm.is_none() {
            errors.push(indexed_issue(
                DidValidationCode::VerificationMethodInvalid,
                DidValidationLocation::VerificationMethod,
                i,
            ));
        }
    }

    // ---------------------------------------------------------------------
    // relationships
    // ---------------------------------------------------------------------
    let rels = [
        &doc.authentication,
        &doc.assertion_method,
        &doc.capability_invocation,
        &doc.key_agreement,
    ];

    for r in rels {
        if !r.iter().all(|s| !s.is_empty()) || has_duplicates(r) {
            errors.push(issue(
                DidValidationCode::RelationshipInvalid,
                DidValidationLocation::Relationship,
            ));
        }
    }

    // ---------------------------------------------------------------------
    // service[]
    // ---------------------------------------------------------------------
    for (i, s) in doc.service.iter().enumerate() {
        if !s.id.starts_with('#') {
            errors.push(indexed_issue(
                DidValidationCode::ServiceInvalid,
                DidValidationLocation::Service,
                i,
            ));
        }

        if s.service_type.is_empty() {
            errors.push(indexed_issue(
                DidValidationCode::ServiceInvalid,
                DidValidationLocation::Service,
                i,
            ));
        }

        if s.service_endpoint.is_null() {
            errors.push(indexed_issue(
                DidValidationCode::ServiceInvalid,
                DidValidationLocation::Service,
                i,
            ));
        }
    }

    // ---------------------------------------------------------------------
    // updatePolicy
    // ---------------------------------------------------------------------
    if let Some(up) = &doc.update_policy {
        if up.allowed_verification_methods.is_empty() && !terminal {
            errors.push(issue(
                DidValidationCode::UpdatePolicyInvalid,
                DidValidationLocation::UpdatePolicy,
            ));
        }
        // Update-policy references use the same fragment-relative form as
        // verification method and attestation ids, so no normalization is needed.
        if !up
            .allowed_verification_methods
            .iter()
            .all(|id| id.len() > 1 && id.starts_with('#'))
        {
            errors.push(issue(
                DidValidationCode::UpdatePolicyInvalid,
                DidValidationLocation::UpdatePolicy,
            ));
        }
        if has_duplicates(&up.allowed_verification_methods) {
            errors.push(issue(
                DidValidationCode::UpdatePolicyInvalid,
                DidValidationLocation::UpdatePolicy,
            ));
        }
        if let Some(threshold) = up.threshold {
            let threshold_usize = usize::try_from(threshold).ok();
            if threshold_usize == Some(0)
                || threshold_usize
                    .map(|value| value > up.allowed_verification_methods.len())
                    .unwrap_or(true)
            {
                errors.push(issue(
                    DidValidationCode::UpdatePolicyInvalid,
                    DidValidationLocation::UpdatePolicy,
                ));
            }
        }
    }

    // ---------------------------------------------------------------------
    // attestations[]
    // ---------------------------------------------------------------------
    for (i, a) in doc.attestations.iter().enumerate() {
        if a.alg.is_empty() {
            errors.push(indexed_issue(
                DidValidationCode::AttestationInvalid,
                DidValidationLocation::Attestation,
                i,
            ));
        }

        if !a.vm.starts_with('#') {
            errors.push(indexed_issue(
                DidValidationCode::AttestationInvalid,
                DidValidationLocation::Attestation,
                i,
            ));
        }

        if a.sig.is_empty() {
            errors.push(indexed_issue(
                DidValidationCode::AttestationInvalid,
                DidValidationLocation::Attestation,
                i,
            ));
        }
    }

    StructureValidationResult {
        ok: errors.is_empty(),
        errors,
    }
}

fn exceeds_resource_limits(doc: &DIDDocument) -> bool {
    let controller_count = match &doc.controller {
        Controller::Single(_) => 1,
        Controller::Multiple(values) => values.len(),
    };
    let allowed_count = doc
        .update_policy
        .as_ref()
        .map_or(0, |policy| policy.allowed_verification_methods.len());

    doc.context.len() > MAX_CONTEXT_ENTRIES
        || controller_count > MAX_CONTROLLERS
        || doc.also_known_as.len() > MAX_ALSO_KNOWN_AS
        || doc.verification_method.len() > MAX_VERIFICATION_METHODS
        || doc.authentication.len() > MAX_RELATIONSHIP_REFERENCES
        || doc.assertion_method.len() > MAX_RELATIONSHIP_REFERENCES
        || doc.capability_invocation.len() > MAX_RELATIONSHIP_REFERENCES
        || doc.key_agreement.len() > MAX_RELATIONSHIP_REFERENCES
        || allowed_count > MAX_RELATIONSHIP_REFERENCES
        || doc.service.len() > MAX_SERVICES
        || doc.attestations.len() > MAX_ATTESTATIONS
        || doc.domain_verification.len() > MAX_DOMAIN_VERIFICATIONS
        || doc.key_history.len() > MAX_KEY_HISTORY_ENTRIES
        || doc.core_cbor.len() > MAX_CORE_CBOR_ENCODED_BYTES
}

fn has_duplicates(values: &[String]) -> bool {
    let mut seen = HashSet::new();
    values.iter().any(|value| !seen.insert(value.as_str()))
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
