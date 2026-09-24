// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::validate::{
    validate_all_domain_bindings, validate_attestation_policy, validate_attestations,
    validate_core_snapshot, validate_data_integrity_proof_schema, validate_did_me_structure,
    validate_domain_entry, validate_projection, validate_services, validate_update_policy,
    validate_verification_methods, DidDocumentViewForDV, DomainVerificationEnv,
};
use crate::validate::{DidValidationCode, DidValidationIssue, DidValidationLocation};

use reallyme_did_types::DIDDocument;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Result of full did:me DID Document validation.
pub struct FullValidationResult {
    /// Whether all required validation checks succeeded.
    pub ok: bool,

    /// Stable validation diagnostics collected for callers and tests.
    pub errors: Vec<DidValidationIssue>,

    /// Non-fatal validation issues, typically for skipped external domain verification.
    pub warnings: Vec<DidValidationIssue>,

    /// Decoded canonical core value when core validation succeeds far enough to return it.
    pub core: Option<reallyme_codec::cbor::CborValue>,
}

impl core::fmt::Debug for FullValidationResult {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("FullValidationResult")
            .field("ok", &self.ok)
            .field("error_count", &self.errors.len())
            .field("warning_count", &self.warnings.len())
            .field("core", &self.core.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

impl FullValidationResult {
    /// Transfer stable error diagnostics while retaining ownership of decoded core state.
    ///
    /// `FullValidationResult` deliberately implements `Drop`, so callers must not move
    /// fields out directly. Taking only the privacy-safe diagnostics lets the remaining
    /// owner clear decoded canonical state when it leaves scope.
    pub fn take_errors(&mut self) -> Vec<DidValidationIssue> {
        core::mem::take(&mut self.errors)
    }

    /// Transfer stable warning diagnostics while retaining ownership of decoded core state.
    pub fn take_warnings(&mut self) -> Vec<DidValidationIssue> {
        core::mem::take(&mut self.warnings)
    }
}

impl Drop for FullValidationResult {
    fn drop(&mut self) {
        if let Some(core) = &mut self.core {
            zeroize_cbor_value(core);
        }
        self.core = None;
    }
}

impl ZeroizeOnDrop for FullValidationResult {}

/// Full DID Document validator.
pub fn validate_did_document(
    doc: &DIDDocument,
    env: DomainVerificationEnv,
) -> FullValidationResult {
    let mut errors = Vec::new();
    let mut warnings = Vec::new();

    // ---------------------------------------------------------------------
    // 1. Structural validation
    // ---------------------------------------------------------------------
    let structural = validate_did_me_structure(doc);
    errors.extend(structural.errors);

    if !structural.ok {
        return FullValidationResult {
            ok: false,
            errors,
            warnings,
            core: None,
        };
    }

    // ---------------------------------------------------------------------
    // 2. Core snapshot validation
    // ---------------------------------------------------------------------
    let core_result = validate_core_snapshot(crate::validate::DidMeDocCoreView {
        id: &doc.id,
        controller: &doc.controller,
        sequence: doc.sequence,
        prev: doc.prev.as_deref(),
        current_core: &doc.current_core,
        core_cbor: &doc.core_cbor,
    });

    errors.extend(core_result.errors.clone());
    warnings.extend(core_result.warnings.clone());

    if !core_result.ok {
        return FullValidationResult {
            ok: false,
            errors,
            warnings,
            core: core_result.core,
        };
    }

    let core = match core_result.core.clone() {
        Some(c) => c,
        None => {
            errors.push(internal_invariant_issue());
            return FullValidationResult {
                ok: false,
                errors,
                warnings,
                core: None,
            };
        }
    };
    let terminal = is_terminal_deactivation_shape(doc);

    // ---------------------------------------------------------------------
    // 3. Projection validation
    // ---------------------------------------------------------------------
    let proj = validate_projection(doc, &core);
    errors.extend(proj.errors);

    // ---------------------------------------------------------------------
    // 4. Attestations
    // ---------------------------------------------------------------------
    if !doc.attestations.is_empty() && !terminal {
        let att =
            validate_attestations(&doc.verification_method, &doc.attestations, &doc.core_cbor);
        errors.extend(att.errors);
    }

    if !terminal {
        if let Some(update_policy) = &doc.update_policy {
            let att_policy = validate_attestation_policy(update_policy, &doc.attestations);
            errors.extend(att_policy.errors);
        }
    }

    // ---------------------------------------------------------------------
    // 5. Data Integrity Proof (non-authoritative anchor)
    // ---------------------------------------------------------------------
    if doc.data_integrity_proof.is_some() {
        let dip = validate_data_integrity_proof_schema(doc);
        // The optional Data Integrity proof is useful anchor metadata, but the
        // did:me core and attestations determine DID validity. Report proof
        // shape issues without allowing them to invalidate an otherwise valid
        // DID document.
        warnings.extend(dip.errors);
    }

    // ---------------------------------------------------------------------
    // 6a. Domain binding (no network)
    // ---------------------------------------------------------------------
    let binding_errs = validate_all_domain_bindings(&doc.id, &doc.domain_verification);
    errors.extend(binding_errs);

    // ---------------------------------------------------------------------
    // 6b. Domain verification (with env)
    // ---------------------------------------------------------------------
    let dv_view = DidDocumentViewForDV { id: &doc.id };

    for dv in &doc.domain_verification {
        // If external resolvers are not provided, treat as "unverified" rather than an error.
        // This keeps DID validation deterministic and allows multi-platform callers to supply
        // DNS/HTTP domain responses separately.
        match dv.method.as_str() {
            "dns" if env.resolve_txt.is_none() => {
                warnings.push(domain_verification_skipped_issue());
                continue;
            }
            "wellknown" if env.fetch_url.is_none() => {
                warnings.push(domain_verification_skipped_issue());
                continue;
            }
            _ => {}
        }

        match validate_domain_entry(dv, &dv_view, &env) {
            Ok(true) => {}
            Ok(false) => errors.push(domain_verification_failed_issue()),
            Err(_) => errors.push(domain_verification_unavailable_issue()),
        }
    }

    // ---------------------------------------------------------------------
    // 7. Verification method semantics
    // ---------------------------------------------------------------------
    let vm = validate_verification_methods(doc);
    errors.extend(vm.errors);

    // ---------------------------------------------------------------------
    // 8. Services
    // ---------------------------------------------------------------------
    let svc = validate_services(doc);
    errors.extend(svc.errors);

    // ---------------------------------------------------------------------
    // 9. UpdatePolicy
    // ---------------------------------------------------------------------
    let up = validate_update_policy(doc);
    errors.extend(up.errors);

    let ok = errors.is_empty();

    FullValidationResult {
        ok,
        errors,
        warnings,
        core: Some(core),
    }
}

fn internal_invariant_issue() -> DidValidationIssue {
    DidValidationIssue::new(
        DidValidationCode::InternalInvariantViolation,
        DidValidationLocation::Document,
    )
}

fn domain_verification_skipped_issue() -> DidValidationIssue {
    DidValidationIssue::new(
        DidValidationCode::DomainVerificationSkipped,
        DidValidationLocation::DomainVerification,
    )
}

fn domain_verification_failed_issue() -> DidValidationIssue {
    DidValidationIssue::new(
        DidValidationCode::DomainVerificationFailed,
        DidValidationLocation::DomainVerification,
    )
}

fn domain_verification_unavailable_issue() -> DidValidationIssue {
    DidValidationIssue::new(
        DidValidationCode::DomainVerificationUnavailable,
        DidValidationLocation::DomainVerification,
    )
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

fn zeroize_cbor_value(value: &mut reallyme_codec::cbor::CborValue) {
    use reallyme_codec::cbor::CborValue;

    match value {
        CborValue::String(text) => text.zeroize(),
        CborValue::Bytes(bytes) => bytes.zeroize(),
        CborValue::Array(values) => {
            for child in values.iter_mut() {
                zeroize_cbor_value(child);
            }
            values.clear();
        }
        CborValue::Map(entries) => {
            for (key, child) in entries.iter_mut() {
                key.zeroize();
                zeroize_cbor_value(child);
            }
            entries.clear();
        }
        CborValue::Null | CborValue::Bool(_) | CborValue::Int(_) => {}
        _ => {}
    }
    *value = CborValue::Null;
}
