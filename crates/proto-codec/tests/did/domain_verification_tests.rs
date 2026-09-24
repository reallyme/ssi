// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Test coverage for this crate.
#![allow(missing_docs)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::panic)]
#![allow(clippy::expect_used)]

use reallyme_did_types::{DNSBinding, DomainVerification, WellKnownBinding};
use reallyme_ssi_proto::generated::proto::meid::did::v1::{
    domain_verification::Binding, DNSBinding as PbDNSBinding,
    DomainVerification as PbDomainVerification, WellKnownBinding as PbWellKnownBinding,
};
use reallyme_ssi_proto_codec::did::mapping::domain_verification::{
    domain_from_proto, domain_to_proto,
};

#[test]
fn json_to_proto_dns_binding() {
    let json = DomainVerification {
        verification_type: "DnsTxtVerification".to_string(),
        method: "dns".to_string(),
        domain: "example.com".to_string(),
        dns: Some(DNSBinding {
            record_name: "_did".to_string(),
            txt_value: "did:me:123".to_string(),
        }),
        wellknown: None,
    };

    let proto = domain_to_proto(&json).expect("json to proto");

    assert_eq!(proto.r#type, "DnsTxtVerification");
    assert_eq!(proto.domain, "example.com");
    assert_eq!(proto.method, "dns");

    match proto.binding {
        Some(Binding::Dns(dns)) => {
            assert_eq!(dns.record_name, "_did");
            assert_eq!(dns.txt_value, "did:me:123");
        }
        _ => panic!("expected DNS binding"),
    }
}

#[test]
fn json_to_proto_wellknown_binding() {
    let json = DomainVerification {
        verification_type: "HttpsWellKnownVerification".to_string(),
        method: "wellknown".to_string(),
        domain: "example.org".to_string(),
        dns: None,
        wellknown: Some(WellKnownBinding {
            uri: "/.well-known/did-configuration.json".to_string(),
            content: "did:me:xyz".to_string(),
        }),
    };

    let proto = domain_to_proto(&json).expect("json to proto");

    assert_eq!(proto.r#type, "HttpsWellKnownVerification");
    assert_eq!(proto.domain, "example.org");
    assert_eq!(proto.method, "wellknown");

    match proto.binding {
        Some(Binding::WellKnown(wk)) => {
            assert_eq!(wk.uri, "/.well-known/did-configuration.json");
            assert_eq!(wk.content, "did:me:xyz");
        }
        _ => panic!("expected WellKnown binding"),
    }
}

#[test]
fn proto_to_json_dns_binding() {
    let proto = PbDomainVerification {
        r#type: "DnsTxtVerification".to_string(),
        domain: "example.net".to_string(),
        method: "dns".to_string(),
        binding: Some(Binding::Dns(Box::new(PbDNSBinding {
            record_name: "_did".to_string(),
            txt_value: "did:me:abc".to_string(),
            ..PbDNSBinding::default()
        }))),
        ..PbDomainVerification::default()
    };

    let json = domain_from_proto(&proto).expect("proto to json");

    assert_eq!(json.verification_type, "DnsTxtVerification");
    assert_eq!(json.domain, "example.net");
    assert_eq!(json.method, "dns");
    assert!(json.wellknown.is_none());

    let dns = json.dns.as_ref().expect("dns binding missing");
    assert_eq!(dns.record_name, "_did");
    assert_eq!(dns.txt_value, "did:me:abc");
}

#[test]
fn proto_to_json_wellknown_binding() {
    let proto = PbDomainVerification {
        r#type: "HttpsWellKnownVerification".to_string(),
        domain: "example.io".to_string(),
        method: "wellknown".to_string(),
        binding: Some(Binding::WellKnown(Box::new(PbWellKnownBinding {
            uri: "/.well-known/did-configuration.json".to_string(),
            content: "did:me:def".to_string(),
            ..PbWellKnownBinding::default()
        }))),
        ..PbDomainVerification::default()
    };

    let json = domain_from_proto(&proto).expect("proto to json");

    assert_eq!(json.verification_type, "HttpsWellKnownVerification");
    assert_eq!(json.domain, "example.io");
    assert_eq!(json.method, "wellknown");
    assert!(json.dns.is_none());

    let wk = json.wellknown.as_ref().expect("wellknown binding missing");
    assert_eq!(wk.uri, "/.well-known/did-configuration.json");
    assert_eq!(wk.content, "did:me:def");
}

#[test]
fn roundtrip_dns_binding() {
    let original = DomainVerification {
        verification_type: "DnsTxtVerification".to_string(),
        method: "dns".to_string(),
        domain: "roundtrip.example".to_string(),
        dns: Some(DNSBinding {
            record_name: "_did".to_string(),
            txt_value: "did:me:roundtrip".to_string(),
        }),
        wellknown: None,
    };

    let proto = domain_to_proto(&original).expect("json to proto");
    let decoded = domain_from_proto(&proto).expect("proto to json");

    assert_eq!(decoded.verification_type, original.verification_type);
    assert_eq!(decoded.domain, original.domain);
    assert_eq!(decoded.method, original.method);
    assert_eq!(
        decoded.dns.as_ref().unwrap().txt_value,
        original.dns.as_ref().unwrap().txt_value
    );
}
