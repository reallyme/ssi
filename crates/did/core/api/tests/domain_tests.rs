// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Test coverage for this crate.
#![allow(missing_docs)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::panic)]
#![allow(clippy::expect_used)]

use reallyme_did_api::{
    validate_did_domain, validate_domain_bindings, validate_single_domain_binding,
    SingleDomainValidationError,
};
use reallyme_did_core::validate::{
    DidValidationCode, DomainVerificationEnv, DomainVerificationError,
};
use reallyme_did_types::{DIDDocument, DNSBinding, DomainVerification, WellKnownBinding};

fn make_doc(dv: Vec<DomainVerification>) -> DIDDocument {
    let mut document = DIDDocument::default();
    document.id = "did:me:test".into();
    document.domain_verification = dv;
    document
}

#[test]
fn dns_domain_verification_succeeds() {
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

    let env = DomainVerificationEnv {
        resolve_txt: Some(&|_domain| Ok(vec!["did:me:test".into()])),
        fetch_url: None,
    };

    let res = validate_single_domain_binding("did:me:test", &dv, &env);

    assert!(res.ok);
    assert!(res.error.is_none());
}

#[test]
fn dns_domain_verification_fails_on_mismatch() {
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

    let env = DomainVerificationEnv {
        resolve_txt: Some(&|_domain| Ok(vec!["did:me:other".into()])),
        fetch_url: None,
    };

    let res = validate_single_domain_binding("did:me:test", &dv, &env);

    assert!(!res.ok);
}

#[test]
fn wellknown_domain_verification_succeeds() {
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

    let env = DomainVerificationEnv {
        resolve_txt: None,
        fetch_url: Some(&|_url| Ok(r#"{"domain":"example.com","did":"did:me:test"}"#.into())),
    };

    let res = validate_single_domain_binding("did:me:test", &dv, &env);

    assert!(res.ok);
}

#[test]
fn wellknown_domain_verification_rejects_noncanonical_uri_forms() {
    for uri in [
        ".well-known/did-configuration.json",
        "http://example.com/config",
    ] {
        let dv = DomainVerification {
            verification_type: "HttpsWellKnownVerification".into(),
            method: "wellknown".into(),
            domain: "example.com".into(),
            dns: None,
            wellknown: Some(WellKnownBinding {
                uri: uri.into(),
                content: "did:me:test".into(),
            }),
        };

        let env = DomainVerificationEnv {
            resolve_txt: None,
            fetch_url: Some(&|_url| Ok(r#"{"domain":"example.com","did":"did:me:test"}"#.into())),
        };

        let result = validate_single_domain_binding("did:me:test", &dv, &env);
        assert!(!result.ok);
        assert_eq!(
            result.error,
            Some(SingleDomainValidationError::Verification(
                DomainVerificationError::InvalidWellKnownUri
            ))
        );
    }
}

#[test]
fn validate_domain_bindings_collects_errors() {
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

    let doc = make_doc(vec![dv]);

    let env = DomainVerificationEnv {
        resolve_txt: Some(&|_domain| Ok(vec!["wrong".into()])),
        fetch_url: None,
    };

    let (ok, errors) = validate_domain_bindings(&doc, &env);

    assert!(!ok);
    assert_eq!(errors.len(), 1);
    assert_eq!(errors[0].code, DidValidationCode::DomainVerificationFailed);
}

#[test]
fn dns_domain_verification_preserves_typed_resolver_failure() {
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

    let env = DomainVerificationEnv {
        resolve_txt: Some(&|_domain| Err(DomainVerificationError::ResolveTxtFailed)),
        fetch_url: None,
    };

    let res = validate_single_domain_binding("did:me:test", &dv, &env);

    assert!(!res.ok);
    assert_eq!(
        res.error,
        Some(SingleDomainValidationError::Verification(
            DomainVerificationError::ResolveTxtFailed
        ))
    );
}

#[test]
fn validate_did_domain_no_bindings_is_ok() {
    let doc = make_doc(vec![]);

    let env = DomainVerificationEnv {
        resolve_txt: None,
        fetch_url: None,
    };

    let (ok, errors) = validate_did_domain(&doc, &env);

    assert!(ok);
    assert!(errors.is_empty());
}
