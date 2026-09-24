// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Test coverage for this crate.
#![allow(missing_docs)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::panic)]
#![allow(clippy::expect_used)]

use identity_core_primitives::Algorithm;
use reallyme_did_core::{sign_core, CoreVerificationMethod};
use std::collections::HashMap;

// bring in helper
mod helpers;
use helpers::test_core;

#[test]
fn only_allowed_and_supported_keys_sign() {
    // --------------------------------------------------
    // 1. Build a valid core via helper
    // --------------------------------------------------
    let core = test_core(1, None);

    // --------------------------------------------------
    // 2. Define verification methods
    // --------------------------------------------------
    let keys = vec![
        CoreVerificationMethod {
            id: "#ed25519".into(),
            vm_type: "Multikey".into(),
            algorithm: Algorithm::Ed25519,
            public_key_multibase: "zKey".into(),
        },
        CoreVerificationMethod {
            id: "#x25519".into(),
            vm_type: "Multikey".into(),
            algorithm: Algorithm::X25519,
            public_key_multibase: "zKey".into(),
        },
    ];

    // --------------------------------------------------
    // 3. Provide secrets (only Ed25519 matters)
    // --------------------------------------------------
    let mut secrets: HashMap<String, Vec<u8>> = HashMap::new();

    secrets.insert("#ed25519".into(), vec![1u8; 32]);
    secrets.insert("#x25519".into(), vec![2u8; 32]); // ignored (non-signing)

    // --------------------------------------------------
    // 4. Sign
    // --------------------------------------------------
    let attestations = sign_core(&core, &keys, &["#ed25519".into()], |id| {
        secrets.get(id).cloned()
    })
    .unwrap();

    // --------------------------------------------------
    // 5. Assertions
    // --------------------------------------------------
    assert_eq!(attestations.len(), 1);
    assert_eq!(attestations[0].verification_method, "#ed25519");
}
