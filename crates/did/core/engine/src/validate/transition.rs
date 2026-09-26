// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! did:me update transition validation.
//!
//! A non-genesis core is authorized by the controller keys and update policy of
//! the directly preceding core, not by its own contents. This module binds the
//! next document to the previous canonical core by CID and verifies the next
//! document's attestations with the previous core's committed authority.

use reallyme_did_types::DIDDocument;

use crate::validate::authority::decode_core_authority;
use crate::validate::did_document::{validate_with_authority, AttestationAuthority};
use crate::validate::{
    validate_core_snapshot, DidMeDocCoreView, DidValidationCode, DidValidationIssue,
    DidValidationLocation, DomainVerificationEnv, FullValidationResult,
};

/// Validate `next` as the direct successor of `previous`.
///
/// The previous document supplies the update authority: `next.attestations`
/// must be valid signatures over `next`'s canonical core by controller keys
/// committed in `previous`'s canonical core, satisfying `previous`'s committed
/// update policy. The previous core is bound by CID: `previous.coreCbor` must
/// hash to `previous.currentCore`, which must equal `next.prev`.
///
/// This function authenticates a single step. The caller remains responsible
/// for having established trust in `previous`, either as a validated genesis
/// document or as the head of a previously validated transition chain.
pub fn validate_did_document_transition(
    previous: &DIDDocument,
    next: &DIDDocument,
    env: DomainVerificationEnv,
) -> FullValidationResult {
    let previous_core = validate_core_snapshot(DidMeDocCoreView {
        id: &previous.id,
        controller: &previous.controller,
        sequence: previous.sequence,
        prev: previous.prev.as_deref(),
        current_core: &previous.current_core,
        core_cbor: &previous.core_cbor,
    });

    let previous_core_value = match (previous_core.ok, previous_core.core.as_ref()) {
        (true, Some(value)) => value,
        _ => return transition_invalid_result(),
    };

    if !transition_links_are_valid(previous, next) {
        return transition_invalid_result();
    }

    // A deactivated (terminal) previous state has no update authority left.
    match decode_core_authority(&previous.id, previous_core_value) {
        Some(authority)
            if !authority
                .update_policy
                .allowed_verification_methods
                .is_empty() => {}
        _ => return transition_invalid_result(),
    }

    validate_with_authority(
        next,
        env,
        AttestationAuthority::Previous(previous_core_value),
    )
}

fn transition_links_are_valid(previous: &DIDDocument, next: &DIDDocument) -> bool {
    let Some(expected_sequence) = previous.sequence.checked_add(1) else {
        return false;
    };

    if next.id != previous.id
        || next.sequence != expected_sequence
        || next.prev.as_deref() != Some(previous.current_core.as_str())
    {
        return false;
    }

    // keyHistory must extend the previous history by exactly the previous CID.
    let Some((last, prefix)) = next.key_history.split_last() else {
        return false;
    };
    last == &previous.current_core && prefix == previous.key_history.as_slice()
}

fn transition_invalid_result() -> FullValidationResult {
    FullValidationResult {
        ok: false,
        errors: vec![DidValidationIssue::new(
            DidValidationCode::TransitionInvalid,
            DidValidationLocation::Core,
        )],
        warnings: Vec::new(),
        core: None,
    }
}
