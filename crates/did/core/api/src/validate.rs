// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_did_core::validate::limits::MAX_KEY_HISTORY_ENTRIES;
use reallyme_did_core::validate::validate_did_document as core_validate_did_document;
use reallyme_did_core::validate::validate_did_document_consistency as core_validate_did_document_consistency;
use reallyme_did_core::validate::validate_did_document_transition as core_validate_did_document_transition;
use reallyme_did_method_me::{parse_did_me, verify_genesis_core_identifier};
use reallyme_did_types::DIDDocument;

/// Caller-supplied DNS and well-known responses for offline domain verification.
pub use reallyme_did_core::validate::DomainResponse;
/// Environment containing optional DNS and HTTPS resolver callbacks.
pub use reallyme_did_core::validate::DomainVerificationEnv;
/// Full DID validation result returned by the core validator.
pub use reallyme_did_core::validate::FullValidationResult;
/// Stable DID validation reason codes.
pub use reallyme_did_core::validate::{
    DidValidationCode, DidValidationIssue, DidValidationLocation,
};

/// Maximum number of documents accepted by [`validate_did_chain`].
pub const MAX_DID_CHAIN_DOCUMENTS: usize = MAX_KEY_HISTORY_ENTRIES + 1;

/// High-level DID validator (API facade).
///
/// This composes generic core validation with did:me method identifier binding.
///
/// Only a sequence-one (genesis) document can be fully validated on its own.
/// A document with `sequence >= 2` is authorized by its previous core state and
/// is always reported as invalid here with `TransitionAuthorityUnverified`; use
/// [`validate_did_transition`] or [`validate_did_chain`] instead.
pub fn validate_did(doc: &DIDDocument, env: DomainVerificationEnv) -> FullValidationResult {
    let mut result = core_validate_did_document(doc, env);
    apply_identifier_binding(doc, &mut result);
    result
}

/// Validate `next` as the authorized direct successor of `previous`.
///
/// `next`'s attestations are verified with the controller keys and update
/// policy committed in `previous`'s canonical core. The caller must already
/// trust `previous` (see [`validate_did_chain`] for end-to-end verification).
pub fn validate_did_transition(
    previous: &DIDDocument,
    next: &DIDDocument,
    env: DomainVerificationEnv,
) -> FullValidationResult {
    let mut result = core_validate_did_document_transition(previous, next, env);
    apply_identifier_binding(next, &mut result);
    result
}

/// Validate a complete did:me history from genesis to head.
///
/// `chain[0]` must be the sequence-one genesis document and every following
/// entry must be the authorized direct successor of the one before it. Domain
/// verification callbacks are applied only to the head document; historical
/// entries are validated without external lookups. The returned result
/// describes the head document, or the first failing entry.
pub fn validate_did_chain(
    chain: &[DIDDocument],
    env: DomainVerificationEnv,
) -> FullValidationResult {
    match chain.split_last() {
        Some((head, history)) => validate_did_with_history(history, head, env),
        None => failed_result(
            DidValidationCode::TransitionInvalid,
            DidValidationLocation::Core,
        ),
    }
}

/// Validate `head` against its verified predecessors.
///
/// `history` runs from the genesis document to the document directly preceding
/// `head`; it is empty when `head` is itself the genesis document. This is the
/// borrowed form of [`validate_did_chain`].
pub fn validate_did_with_history(
    history: &[DIDDocument],
    head: &DIDDocument,
    env: DomainVerificationEnv,
) -> FullValidationResult {
    if history.len() >= MAX_DID_CHAIN_DOCUMENTS {
        return failed_result(
            DidValidationCode::ResourceLimitExceeded,
            DidValidationLocation::KeyHistory,
        );
    }

    let mut previous: Option<&DIDDocument> = None;
    for doc in history {
        let result = match previous {
            None => validate_did(doc, no_domain_env()),
            Some(previous_doc) => validate_did_transition(previous_doc, doc, no_domain_env()),
        };
        if !result.ok {
            return result;
        }
        previous = Some(doc);
    }

    match previous {
        None => validate_did(head, env),
        Some(previous_doc) => validate_did_transition(previous_doc, head, env),
    }
}

fn no_domain_env() -> DomainVerificationEnv<'static> {
    DomainVerificationEnv {
        resolve_txt: None,
        fetch_url: None,
    }
}

/// Validate a controller-held DID document's self-consistency.
///
/// For a genesis document this is identical to [`validate_did`]. For a
/// document with `sequence >= 2`, attestation authority cannot be established
/// without the previous state and is reported as a `TransitionAuthorityUnverified`
/// warning. A successful result does not authenticate the document; it only
/// checks local state before the controller publishes a new transition, which
/// must then be verified with [`validate_did_transition`].
pub fn validate_did_consistency(
    doc: &DIDDocument,
    env: DomainVerificationEnv,
) -> FullValidationResult {
    let mut result = core_validate_did_document_consistency(doc, env);
    apply_identifier_binding(doc, &mut result);
    result
}

fn apply_identifier_binding(doc: &DIDDocument, result: &mut FullValidationResult) {
    if parse_did_me(&doc.id).is_err() {
        result.errors.push(DidValidationIssue::new(
            DidValidationCode::IdentifierInvalid,
            DidValidationLocation::Id,
        ));
        result.ok = false;
    }

    if result.ok && doc.sequence == 1 {
        let bound = result
            .core
            .as_ref()
            .is_some_and(|core| verify_genesis_core_identifier(&doc.id, core).is_ok());
        if !bound {
            result.errors.push(DidValidationIssue::new(
                DidValidationCode::IdentifierInvalid,
                DidValidationLocation::Id,
            ));
            result.ok = false;
        }
    }
}

fn failed_result(code: DidValidationCode, location: DidValidationLocation) -> FullValidationResult {
    FullValidationResult {
        ok: false,
        errors: vec![DidValidationIssue::new(code, location)],
        warnings: Vec::new(),
        core: None,
    }
}

/// Validate a DID document using only caller-supplied domain observations.
///
/// This adapter performs no DNS or HTTPS I/O. Missing observations become the
/// validator's stable domain-verification diagnostics through the same core
/// path used by injected native providers.
pub fn validate_did_with_domain_evidence(
    doc: &DIDDocument,
    evidence: &DomainResponse,
) -> FullValidationResult {
    let resolve_txt = |domain: &str| {
        evidence
            .dns_txt
            .get(domain)
            .cloned()
            .ok_or(reallyme_did_core::validate::DomainVerificationError::MissingDnsResponse)
    };
    let fetch_url =
        |url: &str| {
            evidence.wellknown.get(url).cloned().ok_or(
                reallyme_did_core::validate::DomainVerificationError::MissingWellKnownResponse,
            )
        };

    validate_did(
        doc,
        DomainVerificationEnv {
            resolve_txt: Some(&resolve_txt),
            fetch_url: Some(&fetch_url),
        },
    )
}
