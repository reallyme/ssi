// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Test coverage for this crate.
#![allow(missing_docs)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::panic)]
#![allow(clippy::expect_used)]

use reallyme_did_core::{DidCore, UpdatePolicy};

pub fn test_core(sequence: u64, prev: Option<&str>) -> DidCore {
    DidCore {
        id: "did:me:test".into(),
        sequence,
        nonce: if sequence == 1 {
            Some(vec![0; 16])
        } else {
            None
        },
        controller: vec!["did:me:test".into()],
        controller_keys: vec![],
        authentication: vec![],
        assertion: vec![],
        key_agreement: vec![],
        services: vec![],
        update_policy: UpdatePolicy {
            allowed_verification_methods: vec![],
            threshold: None,
        },
        prev: prev.map(|s| s.into()),
    }
}
