// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{Controller, DIDDocument, DNSBinding, DomainVerification, Service};
use zeroize::Zeroize;

#[test]
fn did_document_zeroize_clears_nested_identifying_material() {
    let mut document = DIDDocument::default();
    document.id = "did:me:sensitive".to_owned();
    document.controller = Controller::Multiple(vec!["did:me:controller".to_owned()]);
    document.core_cbor = "sensitive-core".to_owned();
    document.service = vec![Service {
        id: "#private-service".to_owned(),
        service_type: "PrivateService".to_owned(),
        service_endpoint: serde_json::json!({
            "privateKey": "private-value"
        }),
    }];
    document.domain_verification = vec![DomainVerification {
        verification_type: "DnsTxtVerification".to_owned(),
        method: "dns".to_owned(),
        domain: "private.example".to_owned(),
        dns: Some(DNSBinding {
            record_name: "_did".to_owned(),
            txt_value: "did:me:sensitive".to_owned(),
        }),
        wellknown: None,
    }];

    document.zeroize();

    assert!(document.id.is_empty());
    assert!(matches!(document.controller, Controller::Multiple(ref values) if values.is_empty()));
    assert!(document.core_cbor.is_empty());
    assert!(document.service.is_empty());
    assert!(document.domain_verification.is_empty());
}
