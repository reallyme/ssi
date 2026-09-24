// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::{
    PointerTraversalContext, PointerTraversalPolicy, TrustedList, TslError, TslMediaType,
    TslPointer, TslPointerPolicyFailure,
};

/// Validate one app-owned LOTL pointer fetch before its bytes are parsed.
///
/// Network I/O intentionally remains outside this crate. Requiring the caller
/// to supply ancestry and cumulative counters makes cycle, fan-out, and byte
/// budgets explicit and independently testable at every recursive fetch.
pub fn validate_pointer_traversal(
    context: &PointerTraversalContext<'_>,
    policy: &PointerTraversalPolicy,
) -> Result<(), TslError> {
    if context.depth > policy.max_depth {
        return Err(TslError::PointerPolicy(TslPointerPolicyFailure::Depth));
    }
    if context.documents_seen >= policy.max_documents {
        return Err(TslError::PointerPolicy(
            TslPointerPolicyFailure::DocumentCount,
        ));
    }
    let total = context
        .total_bytes_seen
        .checked_add(context.fetched_bytes)
        .ok_or(TslError::PointerPolicy(TslPointerPolicyFailure::TotalBytes))?;
    if total > policy.max_total_bytes {
        return Err(TslError::PointerPolicy(TslPointerPolicyFailure::TotalBytes));
    }
    if policy.require_https && !context.target.is_https() {
        return Err(TslError::PointerPolicy(
            TslPointerPolicyFailure::InsecureTransport,
        ));
    }
    let origin = context
        .target
        .origin()
        .ok_or(TslError::PointerPolicy(TslPointerPolicyFailure::Origin))?;
    if !policy.allowed_origins.contains(&origin) {
        return Err(TslError::PointerPolicy(TslPointerPolicyFailure::Origin));
    }
    if !policy
        .allowed_media_types
        .contains(&context.fetched_media_type)
    {
        return Err(TslError::PointerPolicy(TslPointerPolicyFailure::MediaType));
    }
    if context
        .ancestor_urls
        .iter()
        .any(|ancestor| ancestor == context.target)
    {
        return Err(TslError::PointerPolicy(TslPointerPolicyFailure::Cycle));
    }
    Ok(())
}

/// Bind an authenticated LOTL pointer to the fetched and parsed child list.
///
/// TS 119 612 clause 5.3.13 makes these qualifiers part of the authenticated
/// pointer. Comparing them after parsing prevents a validly signed document at
/// the same URL from being substituted across schemes or communities.
pub fn validate_pointer_target(
    pointer: &TslPointer,
    child: &TrustedList,
    fetched_media_type: TslMediaType,
) -> Result<(), TslError> {
    if pointer.tsl_type != child.tsl_type
        || !has_shared_operator_identity(
            &pointer.scheme_operator_names,
            &child.scheme_operator_names,
        )
        || !has_same_community_rules(
            &pointer.scheme_type_community_rules,
            &child.scheme_type_community_rules,
        )
        || child.scheme_territory.as_deref() != Some(pointer.territory.as_str())
        || pointer.media_type != fetched_media_type
    {
        return Err(TslError::PointerPolicy(
            TslPointerPolicyFailure::TargetMetadataMismatch,
        ));
    }
    Ok(())
}

fn has_shared_operator_identity(
    pointer: &[crate::LocalizedText],
    child: &[crate::LocalizedText],
) -> bool {
    // Multilingual names are sets, not ordered tuples. During an operator-name
    // transition the LOTL and child list can temporarily carry different
    // revisions of the display text. Territory, list type, community-rule
    // URIs, URL, and signer certificate provide the security binding; require
    // a common localized language here without treating display text as an
    // identity key.
    pointer.iter().any(|pointer_name| {
        child
            .iter()
            .any(|child_name| child_name.language == pointer_name.language)
    })
}

fn has_same_community_rules(
    pointer: &[crate::LocalizedUri],
    child: &[crate::LocalizedUri],
) -> bool {
    // The URI is the rule identifier; xml:lang only describes the referenced
    // resource. Compare a deduplicated URI set so language and element order
    // cannot turn equivalent authenticated metadata into a traversal failure.
    pointer.iter().all(|pointer_rule| {
        child
            .iter()
            .any(|child_rule| child_rule.uri == pointer_rule.uri)
    }) && child.iter().all(|child_rule| {
        pointer
            .iter()
            .any(|pointer_rule| pointer_rule.uri == child_rule.uri)
    })
}
