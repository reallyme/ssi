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
use reallyme_did_core::{
    compute_core_cid, verify_core_cid, CanonicalService, CoreVerificationMethod, DidCore,
    UpdatePolicy,
};

#[test]
fn cid_is_deterministic() {
    let core1 = sample_core();
    let core2 = sample_core();

    let cid1 = compute_core_cid(&core1).unwrap();
    let cid2 = compute_core_cid(&core2).unwrap();

    assert_eq!(cid1, cid2);
}

#[test]
fn cid_verification_succeeds() {
    let core = sample_core();
    let cid = compute_core_cid(&core).unwrap();

    let (ok, expected, actual) = verify_core_cid(&cid, &core).unwrap();

    assert!(ok);
    assert_eq!(expected, actual);
}

#[test]
fn cid_verification_fails_when_core_changes() {
    let mut core = sample_core();
    let cid = compute_core_cid(&core).unwrap();

    core.sequence += 1;

    let (ok, _, _) = verify_core_cid(&cid, &core).unwrap();
    assert!(!ok);
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
