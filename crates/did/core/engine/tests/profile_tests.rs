// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Test coverage for this crate.
#![allow(missing_docs)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::panic)]
#![allow(clippy::expect_used)]

use reallyme_did_core::{build_profile, DidProfile};

#[test]
fn core_identity_profile_is_correct() {
    let did = "did:me:test";
    let opts = build_profile(DidProfile::CoreIdentity, did);

    assert_eq!(opts.controller, vec![did]);
    assert_eq!(opts.sequence, 1);
    assert!(opts.prev.is_none());

    assert!(opts.controller_keys.iter().any(|v| v.id == "#mldsa87-root"));
    assert!(opts
        .allowed_verification_methods
        .contains(&"#mldsa87-root".into()));
    assert_eq!(opts.threshold, Some(2));
}

#[test]
fn payment_profile_is_minimal() {
    let did = "did:me:test";
    let opts = build_profile(DidProfile::Payment, did);

    assert_eq!(opts.controller_keys.len(), 1);
    assert_eq!(
        opts.controller_keys[0].algorithm.as_deref(),
        Some("secp256k1")
    );

    assert!(opts.key_agreement.is_empty());
    assert_eq!(opts.threshold, None);
}
