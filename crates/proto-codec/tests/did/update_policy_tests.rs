// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Test coverage for this crate.
#![allow(missing_docs)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::panic)]
#![allow(clippy::expect_used)]

use reallyme_did_types::UpdatePolicy;
use reallyme_ssi_proto_codec::did::mapping::update_policy::{
    policy_to_proto, update_policy_from_proto,
};

#[test]
fn update_policy_roundtrip() {
    let json = UpdatePolicy {
        allowed_verification_methods: vec!["#ed25519".into(), "#mldsa87-root".into()],
        threshold: Some(2),
    };

    let proto = policy_to_proto(&json);
    let out = update_policy_from_proto(&proto);

    assert_eq!(
        out.allowed_verification_methods,
        json.allowed_verification_methods
    );
    assert_eq!(out.threshold, json.threshold);
}

#[test]
fn update_policy_allows_absent_threshold() {
    let json = UpdatePolicy {
        allowed_verification_methods: vec!["#ed25519".into()],
        threshold: None,
    };

    let proto = policy_to_proto(&json);
    let out = update_policy_from_proto(&proto);

    assert_eq!(out.allowed_verification_methods, vec!["#ed25519"]);
    assert_eq!(out.threshold, None);
}

#[test]
fn update_policy_preserves_ordering() {
    let json = UpdatePolicy {
        allowed_verification_methods: vec!["#a".into(), "#b".into(), "#c".into()],
        threshold: Some(3),
    };

    let proto = policy_to_proto(&json);
    let out = update_policy_from_proto(&proto);

    assert_eq!(
        out.allowed_verification_methods,
        json.allowed_verification_methods
    );
    assert_eq!(out.threshold, Some(3));
}
