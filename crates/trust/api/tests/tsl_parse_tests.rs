// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::print_stderr
)]
//! Tests for trust-list XML parsing.

use identity_credential_trust_api::{
    parse_trust_list_xml, TrustApiError, TrustedListPolicyErrorReason,
};

#[test]
fn parses_schema_shaped_tsl() {
    let xml = include_str!("../../tsl-openssl/tests/fixtures/signed_tsl.xml");

    let tsl = parse_trust_list_xml(xml).expect("TSL parsing should succeed");

    assert_eq!(tsl.name, "MT:Test Trusted List");
}

#[test]
fn preserves_typed_tag_and_update_window_failures() {
    let fixture = include_str!("../../tsl-openssl/tests/fixtures/signed_tsl.xml");
    let invalid_tag = fixture.replacen(
        "TSLTag=\"http://uri.etsi.org/19612/TSLTag\"",
        "TSLTag=\"https://example.test/not-a-tsl-tag\"",
        1,
    );
    let invalid_window = fixture.replacen(
        "<dateTime>2027-03-15T01:00:00Z</dateTime>",
        "<dateTime>2027-03-15T02:00:00.000000001Z</dateTime>",
        1,
    );

    assert!(matches!(
        parse_trust_list_xml(&invalid_tag),
        Err(TrustApiError::TrustedListPolicy(
            TrustedListPolicyErrorReason::InvalidTag
        ))
    ));
    assert!(matches!(
        parse_trust_list_xml(&invalid_window),
        Err(TrustApiError::TrustedListPolicy(
            TrustedListPolicyErrorReason::InvalidUpdateWindow
        ))
    ));
}
