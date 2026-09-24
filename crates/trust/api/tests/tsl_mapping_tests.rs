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
//! Tests for TSL mapping into trust API types.

use identity_trust_tsl_core::parse_tsl_xml;

#[test]
fn parse_schema_shaped_tsl() {
    let xml = include_str!("../../tsl-openssl/tests/fixtures/signed_tsl.xml");
    let tsl = parse_tsl_xml(xml).unwrap();

    assert_eq!(tsl.name, "MT:Test Trusted List");
}
