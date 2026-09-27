// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Duplicate-rejecting did:web JSON boundary regression tests.

use reallyme_did_method_web::{
    parse_and_validate_did_web_document, parse_did_web, DidWebDocumentLimits, DidWebErrorReason,
};

const DID: &str = "did:web:example.com";

#[test]
fn rejects_duplicate_document_members() -> Result<(), Box<dyn std::error::Error>> {
    let identifier = parse_did_web(DID)?;
    let bytes = br#"{"id":"did:web:attacker.example","id":"did:web:example.com"}"#;
    assert_eq!(
        parse_and_validate_did_web_document(&identifier, bytes, DidWebDocumentLimits::default())
            .err()
            .map(|error| error.reason),
        Some(DidWebErrorReason::InvalidDocument)
    );
    Ok(())
}
