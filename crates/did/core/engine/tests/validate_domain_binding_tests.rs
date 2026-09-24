// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Test coverage for this crate.
#![allow(missing_docs)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::panic)]
#![allow(clippy::expect_used)]

use reallyme_did_core::validate::{
    validate_all_domain_bindings, validate_domain_binding, DidValidationCode,
};
use reallyme_did_types::{DNSBinding, DomainVerification, WellKnownBinding};

#[test]
fn dns_binding_valid() {
    let dv = DomainVerification {
        verification_type: "DnsTxtVerification".into(),
        method: "dns".into(),
        domain: "example.com".into(),
        dns: Some(DNSBinding {
            record_name: "_did".into(),
            txt_value: "did:me:test".into(),
        }),
        wellknown: None,
    };

    assert!(validate_domain_binding("did:me:test", &dv).is_none());
}

#[test]
fn dns_binding_wrong_value_fails() {
    let dv = DomainVerification {
        verification_type: "DnsTxtVerification".into(),
        method: "dns".into(),
        domain: "example.com".into(),
        dns: Some(DNSBinding {
            record_name: "_did".into(),
            txt_value: "did:me:other".into(),
        }),
        wellknown: None,
    };

    let err = validate_domain_binding("did:me:test", &dv).unwrap();
    assert_eq!(err.code, DidValidationCode::DomainBindingInvalid);
}

#[test]
fn wellknown_binding_valid() {
    let dv = DomainVerification {
        verification_type: "HttpsWellKnownVerification".into(),
        method: "wellknown".into(),
        domain: "example.com".into(),
        dns: None,
        wellknown: Some(WellKnownBinding {
            uri: "/.well-known/did-configuration.json".into(),
            content: "did:me:test".into(),
        }),
    };

    assert!(validate_domain_binding("did:me:test", &dv).is_none());
}

#[test]
fn validate_all_collects_errors() {
    let dv = DomainVerification {
        verification_type: "DnsTxtVerification".into(),
        method: "dns".into(),
        domain: "example.com".into(),
        dns: Some(DNSBinding {
            record_name: "wrong".into(),
            txt_value: "did:me:test".into(),
        }),
        wellknown: None,
    };

    let errs = validate_all_domain_bindings("did:me:test", &[dv]);
    assert_eq!(errs.len(), 1);
}
