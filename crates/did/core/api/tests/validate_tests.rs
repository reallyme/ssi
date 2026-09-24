// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Test coverage for this crate.
#![allow(missing_docs)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::panic)]
#![allow(clippy::expect_used)]

use reallyme_did_api::validate::{validate_did, DidValidationCode};
use reallyme_did_core::validate::DomainVerificationEnv;
use reallyme_did_types::DIDDocument;

#[test]
fn api_validate_delegates_to_core() {
    let mut doc = DIDDocument::default();
    doc.id = "did:me:test".into();

    let env = DomainVerificationEnv {
        resolve_txt: None,
        fetch_url: None,
    };

    let res = validate_did(&doc, env);

    // Structural validation should fail for empty doc
    assert!(!res.ok);
    assert!(!res.errors.is_empty());
}

#[test]
fn api_validate_rejects_non_bech32_did_me_identifier() {
    let mut doc = DIDDocument::default();
    doc.id = "did:me:test".into();

    let env = DomainVerificationEnv {
        resolve_txt: None,
        fetch_url: None,
    };

    let res = validate_did(&doc, env);

    assert!(!res.ok);
    assert!(
        res.errors
            .iter()
            .any(|issue| issue.code == DidValidationCode::IdentifierInvalid),
        "errors: {:?}",
        res.errors
    );
}
