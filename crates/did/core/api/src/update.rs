// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::error::DidApiError;
use crate::validate::{validate_did_transition, DomainVerificationEnv, FullValidationResult};
use reallyme_keys::KeySet;

use reallyme_did_core::update::{
    update_engine, UpdateError, UpdateMetadata, UpdateOptions, UpdateRelationships,
};

use reallyme_did_types::{DIDDocument, DomainVerification, Service};

/// Developer-facing update instructions (TS mirror)
#[derive(Debug, Clone)]
pub struct UpdateConfig {
    /// Replacement service list, or `None` to preserve services.
    pub services: Option<Vec<Service>>,

    /// Replacement `alsoKnownAs` values.
    pub also_known_as: Option<Vec<String>>,

    /// Replacement hardware-bound metadata.
    pub hardware_bound: Option<bool>,

    /// Replacement biometric-protection metadata.
    pub biometric_protected: Option<bool>,

    /// Replacement user verification method metadata.
    pub user_verification_method: Option<String>,

    /// Replacement device model metadata.
    pub device_model: Option<String>,

    /// Replacement update-policy allowed verification methods.
    pub allowed: Option<Vec<String>>,

    /// Replacement update-policy threshold.
    pub threshold: Option<u64>,

    /// Publish the terminal deactivation core.
    pub deactivate: bool,

    /// Replacement domain verification claims.
    pub domain_verification: Option<Vec<DomainVerification>>,

    /// Verification method references whose key material should be rotated.
    pub rotate_vms: Option<Vec<String>>,

    /// Replacement authentication relationship references.
    pub authentication: Option<Vec<String>>,

    /// Replacement assertionMethod relationship references.
    pub assertion: Option<Vec<String>>,

    /// Replacement capabilityInvocation relationship references.
    ///
    /// In did:me this is an alias for `updatePolicy.allowedVerificationMethods`;
    /// if both `allowed` and `invocation` are supplied, they must be identical.
    pub invocation: Option<Vec<String>>,

    /// Replacement keyAgreement relationship references.
    pub key_agreement: Option<Vec<String>>,

    /// Host-supplied RFC3339 timestamp for regenerated proofs.
    pub created: Option<String>,
}

/// Typed relationship assignment request for the dids.keys.set_relationships command.
#[derive(Debug, Clone, Default)]
pub struct RelationshipAssignmentConfig {
    /// Replacement authentication relationship references.
    pub authentication: Option<Vec<String>>,

    /// Replacement assertionMethod relationship references.
    pub assertion: Option<Vec<String>>,

    /// Replacement capabilityInvocation relationship references.
    ///
    /// did:me expresses delegated update authority through
    /// `updatePolicy.allowedVerificationMethods`, so this field updates both
    /// the projected relationship and the authoritative update policy.
    pub invocation: Option<Vec<String>>,

    /// Replacement keyAgreement relationship references.
    pub key_agreement: Option<Vec<String>>,

    /// Replacement update-policy threshold when capabilityInvocation changes.
    pub threshold: Option<u64>,

    /// Host-supplied RFC3339 timestamp for regenerated proofs.
    pub created: Option<String>,
}

/// Command-layer result for deactivation plus validation.
#[derive(Debug)]
pub struct DeactivationResult {
    /// Terminal DID document that should be published or persisted.
    pub document: DIDDocument,

    /// Key material state returned to the caller's storage layer.
    pub keyset: KeySet,

    /// Validation result for the terminal DID document.
    pub validation: FullValidationResult,
}

/// Normalize UpdateConfig → UpdateOptions (engine input)
pub fn build_update_options(
    old_doc: &DIDDocument,
    cfg: UpdateConfig,
) -> Result<UpdateOptions<'_>, DidApiError> {
    let policy = old_doc
        .update_policy
        .as_ref()
        .ok_or(DidApiError::MissingUpdatePolicy)?;

    let allowed = match (cfg.allowed, cfg.invocation) {
        (Some(allowed), Some(invocation)) if allowed == invocation => allowed,
        (Some(_), Some(_)) => return Err(DidApiError::RelationshipAssignmentInvalid),
        (Some(allowed), None) => allowed,
        (None, Some(invocation)) => invocation,
        (None, None) => policy.allowed_verification_methods.clone(),
    };
    let threshold = cfg.threshold.or(policy.threshold);

    let rotate = cfg
        .rotate_vms
        .unwrap_or_default()
        .into_iter()
        .map(|id| (id, true))
        .collect();

    Ok(UpdateOptions {
        old: old_doc,
        rotate,
        allowed,
        threshold,
        deactivate: cfg.deactivate,
        services: cfg.services,
        domain_verification: cfg.domain_verification,
        relationships: UpdateRelationships {
            authentication: cfg.authentication,
            assertion: cfg.assertion,
            key_agreement: cfg.key_agreement,
        },
        metadata: UpdateMetadata {
            also_known_as: cfg.also_known_as,
            hardware_bound: cfg.hardware_bound,
            biometric_protected: cfg.biometric_protected,
            user_verification_method: cfg.user_verification_method,
            device_model: cfg.device_model,
        },
        created: cfg.created,
    })
}

/// High-level updateDid API (exact TS mirror)
pub fn update_did(
    old_doc: &DIDDocument,
    ks: &KeySet,
    cfg: UpdateConfig,
) -> Result<(DIDDocument, KeySet), DidApiError> {
    update_did_with_keysets(old_doc, ks, ks, cfg, &[])
}

/// Update with distinct authorization and post-update key material.
///
/// `authorization_ks` holds the private keys active in `old_doc`: a did:me
/// transition is authorized by the previous core's controller keys, so key
/// rotation must never sign the new core with the replacement keys.
/// `current_ks` holds the key material of the resulting document (rotated
/// public keys and keys for regenerated Data Integrity proofs) and is returned.
pub(crate) fn update_did_with_keysets(
    old_doc: &DIDDocument,
    authorization_ks: &KeySet,
    current_ks: &KeySet,
    cfg: UpdateConfig,
    excluded_authorization_methods: &[String],
) -> Result<(DIDDocument, KeySet), DidApiError> {
    if old_doc.id.is_empty() {
        return Err(DidApiError::MissingOldDocumentId);
    }

    // Clone KeySet (never mutate caller state)
    let mut new_ks = KeySet::new();
    current_ks.copy_into(&mut new_ks);

    // Normalize config → engine options
    let opts = build_update_options(old_doc, cfg)?;

    // Delegate to core update engine
    let doc = update_engine(
        opts,
        |id| {
            if is_excluded_verification_method(&old_doc.id, id, excluded_authorization_methods) {
                return None;
            }

            authorization_ks
                .get_private(id)
                .ok()
                .and_then(|key| (!key.is_empty()).then_some(key.to_vec()))
        },
        |id| {
            new_ks
                .get_private(id)
                .ok()
                .and_then(|key| (!key.is_empty()).then_some(key.to_vec()))
        },
        |id| {
            new_ks
                .get_public(id)
                .ok()
                .and_then(|public_key| (!public_key.is_empty()).then_some(public_key))
        },
    )
    .map_err(map_update_error)?;

    Ok((doc, new_ks))
}

fn is_excluded_verification_method(did: &str, id: &str, excluded: &[String]) -> bool {
    excluded
        .iter()
        .any(|candidate| verification_method_refs_match(did, id, candidate))
}

fn verification_method_refs_match(did: &str, left: &str, right: &str) -> bool {
    if left == right {
        return true;
    }

    if let Some(left_fragment) = left.strip_prefix(did) {
        return left_fragment == right;
    }

    if let Some(right_fragment) = right.strip_prefix(did) {
        return left == right_fragment;
    }

    false
}

fn map_update_error(error: UpdateError) -> DidApiError {
    match error {
        UpdateError::PolicyViolation => DidApiError::PolicyViolation,
        _ => DidApiError::UpdateRejected,
    }
}

/// Publish the terminal deactivation core for a did:me document.
///
/// The transition is authorized by the previously active update policy, just
/// like any other update. The resulting core clears controller keys,
/// relationships, services, and future update authority as required by the
/// did:me deactivation rule.
pub fn deactivate_did(
    old_doc: &DIDDocument,
    ks: &KeySet,
) -> Result<(DIDDocument, KeySet), DidApiError> {
    update_did(
        old_doc,
        ks,
        UpdateConfig {
            services: None,
            also_known_as: None,
            hardware_bound: None,
            biometric_protected: None,
            user_verification_method: None,
            device_model: None,
            allowed: None,
            threshold: None,
            deactivate: true,
            domain_verification: None,
            rotate_vms: None,
            authentication: None,
            assertion: None,
            invocation: None,
            key_agreement: None,
            created: None,
        },
    )
}

/// Publish and validate the terminal deactivation core.
///
/// This is the Rust command-layer shape for the taxonomy `dids.deactivate`
/// output. The terminal document is still returned because callers need it for
/// publication or persistence; the validation result is included so higher
/// layers can expose a `DidValidationResult` without reimplementing did:me
/// terminal-state checks.
pub fn deactivate_did_validated(
    old_doc: &DIDDocument,
    ks: &KeySet,
) -> Result<DeactivationResult, DidApiError> {
    let (document, keyset) = deactivate_did(old_doc, ks)?;
    let validation = validate_did_transition(
        old_doc,
        &document,
        DomainVerificationEnv {
            resolve_txt: None,
            fetch_url: None,
        },
    );

    if !validation.ok {
        return Err(DidApiError::UpdateRejected);
    }

    Ok(DeactivationResult {
        document,
        keyset,
        validation,
    })
}

/// Assign existing verification methods to typed did:me relationships.
///
/// This is the taxonomy `dids.keys.set_relationships` surface. It does not
/// generate or rotate key material; the update engine verifies that every
/// supplied reference exists, belongs to the correct algorithm family for that
/// relationship, and can still satisfy the did:me update policy.
pub fn set_key_relationships(
    old_doc: &DIDDocument,
    ks: &KeySet,
    cfg: RelationshipAssignmentConfig,
) -> Result<(DIDDocument, KeySet), DidApiError> {
    update_did(
        old_doc,
        ks,
        UpdateConfig {
            services: None,
            also_known_as: None,
            hardware_bound: None,
            biometric_protected: None,
            user_verification_method: None,
            device_model: None,
            allowed: cfg.invocation.clone(),
            threshold: cfg.threshold,
            deactivate: false,
            domain_verification: None,
            rotate_vms: None,
            authentication: cfg.authentication,
            assertion: cfg.assertion,
            invocation: cfg.invocation,
            key_agreement: cfg.key_agreement,
            created: cfg.created,
        },
    )
}
