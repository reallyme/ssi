// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_did_core::validate::validate_did_document as core_validate_did_document;
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

/// High-level DID validator (API facade).
///
/// This composes generic core validation with did:me method identifier binding.
pub fn validate_did(doc: &DIDDocument, env: DomainVerificationEnv) -> FullValidationResult {
    let mut result = core_validate_did_document(doc, env);

    if parse_did_me(&doc.id).is_err() {
        result.errors.push(DidValidationIssue::new(
            DidValidationCode::IdentifierInvalid,
            DidValidationLocation::Id,
        ));
        result.ok = false;
    }

    if result.ok && doc.sequence == 1 {
        match result
            .core
            .as_ref()
            .ok_or(())
            .and_then(|core| verify_genesis_core_identifier(&doc.id, core).map_err(|_| ()))
        {
            Ok(()) => {}
            Err(()) => {
                result.errors.push(DidValidationIssue::new(
                    DidValidationCode::IdentifierInvalid,
                    DidValidationLocation::Id,
                ));
                result.ok = false;
            }
        }
    }
    result
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
