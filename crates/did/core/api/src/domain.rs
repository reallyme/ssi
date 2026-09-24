// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_did_core::validate::{
    validate_domain_entry, validate_domain_response, DidDocumentViewForDV, DomainResponse,
    DomainVerificationEnv, DomainVerificationError,
};
use reallyme_did_core::validate::{DidValidationCode, DidValidationIssue, DidValidationLocation};
use reallyme_did_types::{DIDDocument, DomainVerification};
use reallyme_ssi_proto::generated::proto::reallyme::identity_core::v1::IdentityCoreErrorReason;

/// Reason a single domain binding did not validate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SingleDomainValidationError {
    /// The binding resolved successfully but did not match the DID document claim.
    #[error("domain verification failed")]
    VerificationFailed,

    /// The binding could not be checked because of a deterministic core validation error.
    #[error(transparent)]
    Verification(#[from] DomainVerificationError),
}

impl From<SingleDomainValidationError> for IdentityCoreErrorReason {
    fn from(error: SingleDomainValidationError) -> Self {
        match error {
            SingleDomainValidationError::VerificationFailed => {
                Self::IDENTITY_CORE_ERROR_REASON_DID_INVALID_DOMAIN
            }
            SingleDomainValidationError::Verification(error) => error.into(),
        }
    }
}

/// Result of validating a single domain binding
#[derive(Debug)]
pub struct SingleDomainValidationResult {
    /// Whether the binding validated successfully.
    pub ok: bool,

    /// Typed reason for failure when validation did not succeed.
    pub error: Option<SingleDomainValidationError>,
}

/// Validate ONE DomainVerification entry.
///
/// Mirrors TS:
/// validateSingleDomainBinding(did, dv, env)
pub fn validate_single_domain_binding(
    did: &str,
    dv: &DomainVerification,
    env: &DomainVerificationEnv<'_>,
) -> SingleDomainValidationResult {
    let view = DidDocumentViewForDV { id: did };

    match validate_domain_entry(dv, &view, env) {
        Ok(true) => SingleDomainValidationResult {
            ok: true,
            error: None,
        },

        Ok(false) => SingleDomainValidationResult {
            ok: false,
            error: Some(SingleDomainValidationError::VerificationFailed),
        },

        Err(e) => SingleDomainValidationResult {
            ok: false,
            error: Some(SingleDomainValidationError::Verification(e)),
        },
    }
}

/// Validate ALL domainVerification bindings in a DID Document.
///
/// Mirrors TS:
/// validateDomainBindings(doc, env)
pub fn validate_domain_bindings(
    doc: &DIDDocument,
    env: &DomainVerificationEnv<'_>,
) -> (bool, Vec<DidValidationIssue>) {
    let mut errors = Vec::new();

    // Same semantics as TS / Go:
    // no domainVerification = nothing to verify
    if doc.domain_verification.is_empty() {
        return (true, errors);
    }

    for dv in &doc.domain_verification {
        let res = validate_single_domain_binding(&doc.id, dv, env);
        if !res.ok && res.error.is_some() {
            errors.push(domain_issue(DidValidationCode::DomainVerificationFailed));
        }
    }

    (errors.is_empty(), errors)
}

/// Convenience facade:
/// validateDidDomain(doc, env)
pub fn validate_did_domain(
    doc: &DIDDocument,
    env: &DomainVerificationEnv<'_>,
) -> (bool, Vec<DidValidationIssue>) {
    validate_domain_bindings(doc, env)
}

/// Validate domain verification claims against a caller-supplied domain response.
///
/// This performs no network I/O.
pub fn validate_did_with_domain_verification(
    doc: &DIDDocument,
    response: &DomainResponse,
) -> (bool, Vec<DidValidationIssue>) {
    validate_domain_response(doc, response)
}

fn domain_issue(code: DidValidationCode) -> DidValidationIssue {
    DidValidationIssue::new(code, DidValidationLocation::DomainVerification)
}

#[cfg(test)]
#[path = "domain_proto_error_tests.rs"]
mod proto_error_tests;
