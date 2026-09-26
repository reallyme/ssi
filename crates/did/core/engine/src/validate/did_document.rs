// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::validate::authority::decode_core_authority;
use crate::validate::{
    validate_attestation_policy, validate_attestations, validate_core_snapshot,
    validate_data_integrity_proof_schema, validate_did_me_structure, validate_domain_binding,
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

/// Source of the update authority used to verify core attestations.
pub(crate) enum AttestationAuthority<'a> {
    /// Sequence-one genesis core: the core's own controller keys and update
    /// policy authorize it, and the DID identifier commits to that authority.
    Genesis,

    /// Non-genesis core: the directly preceding canonical core authorizes it.
    Previous(&'a reallyme_codec::cbor::CborValue),

    /// Non-genesis core validated without its previous state. Attestation
    /// authority cannot be established; `strict` reports that as an error,
    /// otherwise as a warning for controller-held local state checks.
    Unanchored {
        /// Whether the missing previous state invalidates the document.
        strict: bool,
    },
}

/// Full DID Document validator.
///
/// A sequence-one document is validated completely, including attestations
/// against the genesis core's own committed controller keys and update policy.
///
/// A document with `sequence >= 2` is authorized by the previous core state,
/// which this function does not have. Such documents are never reported as
/// valid here: the result carries a `TransitionAuthorityUnverified` error. Use
/// [`crate::validate::validate_did_document_transition`] with the previous
/// document to authenticate an update.
pub fn validate_did_document(
    doc: &DIDDocument,
    env: DomainVerificationEnv,
) -> FullValidationResult {
    let authority = if doc.sequence == 1 {
        AttestationAuthority::Genesis
    } else {
        AttestationAuthority::Unanchored { strict: true }
    };
    validate_with_authority(doc, env, authority)
}

/// Validate a DID document's self-consistency without establishing update authority.
///
/// This performs every check that can be made from the document alone. For a
/// sequence-one document it is identical to [`validate_did_document`]. For a
/// document with `sequence >= 2` the attestations cannot be authorized without
/// the previous core state, so they are not verified and the result carries a
/// `TransitionAuthorityUnverified` warning instead.
///
/// A successful result does **not** mean the document is authentic. It is only
/// suitable for checking controller-held local state before the controller
/// produces a new transition, which is then authenticated with
/// [`crate::validate::validate_did_document_transition`].
pub fn validate_did_document_consistency(
    doc: &DIDDocument,
    env: DomainVerificationEnv,
) -> FullValidationResult {
    let authority = if doc.sequence == 1 {
        AttestationAuthority::Genesis
    } else {
        AttestationAuthority::Unanchored { strict: false }
    };
    validate_with_authority(doc, env, authority)
}

/// Shared validation pipeline parameterized by the attestation authority source.
pub(crate) fn validate_with_authority(
    doc: &DIDDocument,
    env: DomainVerificationEnv,
    authority: AttestationAuthority<'_>,
) -> FullValidationResult {
    let mut errors = Vec::new();
    let mut warnings = Vec::new();

    // ---------------------------------------------------------------------
    // 1. Structural validation (including resource limits)
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

    errors.extend(core_result.errors.iter().copied());
    warnings.extend(core_result.warnings.iter().copied());

    if !core_result.ok {
        return FullValidationResult {
            ok: false,
            errors,
            warnings,
            core: core_result.core,
        };
    }

    let core = match core_result.core {
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

    // ---------------------------------------------------------------------
    // 3. Projection validation (JSON must match the signed core exactly)
    // ---------------------------------------------------------------------
    let proj = validate_projection(doc, &core);
    errors.extend(proj.errors);

    // ---------------------------------------------------------------------
    // 4. Attestations, verified only against signed core authority
    // ---------------------------------------------------------------------
    let authority_core = match authority {
        AttestationAuthority::Genesis if doc.sequence == 1 => Some(&core),
        AttestationAuthority::Previous(previous_core) if doc.sequence > 1 => Some(previous_core),
        AttestationAuthority::Unanchored { strict } if doc.sequence > 1 => {
            let issue = transition_authority_unverified_issue();
            if strict {
                errors.push(issue);
            } else {
                warnings.push(issue);
            }
            if doc.attestations.is_empty() {
                errors.push(DidValidationIssue::new(
                    DidValidationCode::AttestationPolicyNotSatisfied,
                    DidValidationLocation::Attestation,
                ));
            }
            None
        }
        AttestationAuthority::Genesis
        | AttestationAuthority::Previous(_)
        | AttestationAuthority::Unanchored { .. } => {
            errors.push(DidValidationIssue::new(
                DidValidationCode::TransitionInvalid,
                DidValidationLocation::Core,
            ));
            None
        }
    };

    if let Some(authority_core) = authority_core {
        match decode_core_authority(&doc.id, authority_core) {
            Some(core_authority) => {
                let att = validate_attestations(
                    &core_authority.verification_methods,
                    &doc.attestations,
                    &doc.core_cbor,
                );
                errors.extend(att.errors);

                let att_policy =
                    validate_attestation_policy(&core_authority.update_policy, &doc.attestations);
                errors.extend(att_policy.errors);
            }
            None => errors.push(DidValidationIssue::new(
                DidValidationCode::CoreShapeInvalid,
                DidValidationLocation::Core,
            )),
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
    // 6. Domain binding (no network), then domain verification (with env)
    // ---------------------------------------------------------------------
    let dv_view = DidDocumentViewForDV { id: &doc.id };

    for dv in &doc.domain_verification {
        // A binding that is malformed or not bound to this DID is never
        // dereferenced: no caller-supplied resolver is invoked for it.
        if let Some(issue) = validate_domain_binding(&doc.id, dv) {
            errors.push(issue);
            continue;
        }

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

fn transition_authority_unverified_issue() -> DidValidationIssue {
    DidValidationIssue::new(
        DidValidationCode::TransitionAuthorityUnverified,
        DidValidationLocation::Attestation,
    )
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
