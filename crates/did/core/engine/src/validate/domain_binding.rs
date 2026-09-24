// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0
use reallyme_did_types::DomainVerification;

use crate::validate::diagnostic::{DidValidationCode, DidValidationIssue, DidValidationLocation};

/// Validate ALL domain bindings (no network access)
pub fn validate_all_domain_bindings(
    did: &str,
    bindings: &[DomainVerification],
) -> Vec<DidValidationIssue> {
    let mut errs = Vec::new();

    for dv in bindings {
        if let Some(issue) = validate_domain_binding(did, dv) {
            errs.push(issue);
        }
    }

    errs
}

/// Validate ONE domain binding (pure, no I/O)
pub fn validate_domain_binding(did: &str, dv: &DomainVerification) -> Option<DidValidationIssue> {
    match dv.method.as_str() {
        "dns" if dv.verification_type == "DnsTxtVerification" => validate_dns_binding(did, dv),
        "wellknown" if dv.verification_type == "HttpsWellKnownVerification" => {
            validate_https_binding(did, dv)
        }
        "dns" | "wellknown" => Some(domain_binding_issue()),
        _ => Some(domain_binding_issue()),
    }
}

fn domain_binding_issue() -> DidValidationIssue {
    DidValidationIssue::new(
        DidValidationCode::DomainBindingInvalid,
        DidValidationLocation::DomainVerification,
    )
}

fn validate_dns_binding(did: &str, dv: &DomainVerification) -> Option<DidValidationIssue> {
    let dns = match dv.dns.as_ref() {
        Some(value) => value,
        None => return Some(domain_binding_issue()),
    };

    if dns.record_name != "_did" {
        return Some(domain_binding_issue());
    }

    if dns.txt_value != did {
        return Some(domain_binding_issue());
    }

    None
}

fn validate_https_binding(did: &str, dv: &DomainVerification) -> Option<DidValidationIssue> {
    let wk = match dv.wellknown.as_ref() {
        Some(value) => value,
        None => return Some(domain_binding_issue()),
    };

    if wk.uri != "/.well-known/did-configuration.json" {
        return Some(domain_binding_issue());
    }

    if wk.content != did {
        return Some(domain_binding_issue());
    }

    None
}
