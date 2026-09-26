// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::validate::diagnostic::{DidValidationCode, DidValidationIssue, DidValidationLocation};
use crate::validate::{
    validate_domain_entry, DidDocumentViewForDV, DomainVerificationEnv, DomainVerificationError,
};
use reallyme_did_types::DIDDocument;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Caller-supplied domain responses used to validate `domainVerification` claims.
///
/// This type is intentionally network-free: callers perform DNS/HTTP outside
/// the identity-core engine and supply the raw responses here.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct DomainResponse {
    /// DNS TXT record strings observed for a binding's record name.
    ///
    /// Map: queried record name (`_did.{domain}`) -> TXT strings
    #[serde(default)]
    pub dns_txt: HashMap<String, Vec<String>>,

    /// Well-known response bodies observed for a URL.
    ///
    /// Map: url (`https://{domain}/.well-known/did-configuration.json`) -> raw body string
    ///
    /// For did:me well-known validation, the engine will request:
    /// `https://{domain}{uri}` (for example,
    /// `https://example.com/.well-known/did-configuration.json`).
    #[serde(default)]
    pub wellknown: HashMap<String, String>,
}

/// Validate all `domainVerification` claims in a DID document against a caller-supplied response.
pub fn validate_domain_response(
    doc: &DIDDocument,
    response: &DomainResponse,
) -> (bool, Vec<DidValidationIssue>) {
    if doc.domain_verification.is_empty() {
        return (true, vec![]);
    }

    let resolve_txt = |domain: &str| -> Result<Vec<String>, DomainVerificationError> {
        response
            .dns_txt
            .get(domain)
            .cloned()
            .ok_or(DomainVerificationError::MissingDnsResponse)
    };

    let fetch_url = |url: &str| -> Result<String, DomainVerificationError> {
        response
            .wellknown
            .get(url)
            .cloned()
            .ok_or(DomainVerificationError::MissingWellKnownResponse)
    };

    let env = DomainVerificationEnv {
        resolve_txt: Some(&resolve_txt),
        fetch_url: Some(&fetch_url),
    };

    let view = DidDocumentViewForDV { id: &doc.id };
    let mut errors = Vec::new();

    for dv in &doc.domain_verification {
        match validate_domain_entry(dv, &view, &env) {
            Ok(true) => {}
            Ok(false) => errors.push(domain_issue(DidValidationCode::DomainVerificationFailed)),
            Err(_) => errors.push(domain_issue(
                DidValidationCode::DomainVerificationUnavailable,
            )),
        }
    }

    (errors.is_empty(), errors)
}

fn domain_issue(code: DidValidationCode) -> DidValidationIssue {
    DidValidationIssue::new(code, DidValidationLocation::DomainVerification)
}
