// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Test coverage for this crate.
#![allow(missing_docs)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::panic)]
#![allow(clippy::expect_used)]

use identity_core_primitives::Algorithm;
use reallyme_codec::cbor::CborValue;
use reallyme_did_core::{CanonicalService, CoreVerificationMethod, DidCore, UpdatePolicy};

#[test]
fn did_core_can_be_constructed() {
    let core = sample_core();
    assert_eq!(core.sequence, 1);
    assert_eq!(core.controller.len(), 1);
}

#[test]
fn prev_can_be_none_or_some() {
    let mut core = sample_core();
    core.prev = None;
    assert!(core.prev.is_none());
}

fn sample_core() -> DidCore {
    DidCore {
        id: "did:me:test".into(),
        sequence: 1,
        nonce: Some(vec![0; 16]),
        controller: vec!["did:me:test".into()],
        controller_keys: vec![CoreVerificationMethod {
            id: "#ed25519".into(),
            vm_type: "Multikey".into(),
            algorithm: Algorithm::Ed25519,
            public_key_multibase: "zDummyKey".into(),
        }],
        authentication: vec!["#ed25519".into()],
        assertion: vec!["#ed25519".into()],
        key_agreement: vec![],
        services: vec![CanonicalService {
            id: "#svc".into(),
            service_type: "Messaging".into(),
            service_endpoint: CborValue::Map(vec![(
                "uri".into(),
                CborValue::String("https://example.com".into()),
            )]),
        }],
        update_policy: UpdatePolicy {
            allowed_verification_methods: vec!["#ed25519".into()],
            threshold: None,
        },
        prev: Some("bafyPrevCid".into()),
    }
}
