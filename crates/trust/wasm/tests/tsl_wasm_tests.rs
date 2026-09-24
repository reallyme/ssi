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
//! Tests for WASM TSL trust-evaluation boundaries.
#![cfg(not(target_arch = "wasm32"))]

use identity_trust_wasm::{verify_tsl_xml_wasm, TslWasmError};

use envelopes_x509::policy::X509Policy;
use envelopes_x509::{parse_cert_pem, X509Certificate};

use time::OffsetDateTime;

const SIGNED_TSL_XML: &str = include_str!("../../tsl-openssl/tests/fixtures/signed_tsl.xml");
const TRUST_ROOT_PEM: &[u8] = include_bytes!("../../tsl-openssl/tests/fixtures/cert.pem");

fn trust_root() -> X509Certificate {
    parse_cert_pem(TRUST_ROOT_PEM).expect("invalid trust root PEM")
}

#[test]
fn wasm_tsl_full_verification_is_unavailable() {
    let err = verify_tsl_xml_wasm(
        "Test TSL",
        SIGNED_TSL_XML,
        &[trust_root()],
        OffsetDateTime::from_unix_timestamp(1_800_000_000).expect("fixed test time must be valid"),
        X509Policy::default(),
    )
    .unwrap_err();

    assert!(matches!(err, TslWasmError::XmlDsigUnavailable));
}
