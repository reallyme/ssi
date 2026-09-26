// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::print_stdout,
        clippy::print_stderr
    )
)]

//! Platform-dispatched OCSP response parsing.
//!
//! The public facade delegates to exactly one backend selected by target and
//! Cargo feature. Native builds use OpenSSL and browser WASM uses its runtime
//! binding. Swift and Kotlin provider selection lives in their SDK packages.

use identity_revocation_ocsp_core::{OcspError, ParsedOcspResponse};

#[path = "limits.rs"]
mod limits;

use limits::validate_ocsp_inputs;

#[cfg(all(feature = "native", not(all(feature = "wasm", target_arch = "wasm32"))))]
#[path = "parse_native.rs"]
mod parse_native;

#[cfg(all(feature = "wasm", target_arch = "wasm32"))]
#[path = "parse_wasm.rs"]
mod parse_wasm;

#[cfg(not(any(
    all(feature = "native", not(all(feature = "wasm", target_arch = "wasm32"))),
    all(feature = "wasm", target_arch = "wasm32")
)))]
#[path = "parse_unavailable.rs"]
mod parse_unavailable;

#[cfg(all(feature = "native", not(all(feature = "wasm", target_arch = "wasm32"))))]
use parse_native as selected_backend;

#[cfg(all(feature = "wasm", target_arch = "wasm32"))]
use parse_wasm as selected_backend;

#[cfg(not(any(
    all(feature = "native", not(all(feature = "wasm", target_arch = "wasm32"))),
    all(feature = "wasm", target_arch = "wasm32")
)))]
use parse_unavailable as selected_backend;

/// Parse and optionally verify an OCSP response in DER form.
pub fn parse_ocsp_response_der(
    ocsp_response_der: &[u8],
    cert_der: &[u8],
    issuer_der: &[u8],
    extra_certs_der: &[Vec<u8>],
    now_unix: u64,
) -> Result<ParsedOcspResponse, OcspError> {
    validate_ocsp_inputs(ocsp_response_der, cert_der, issuer_der, extra_certs_der)?;
    selected_backend::parse_ocsp_response_der(
        ocsp_response_der,
        cert_der,
        issuer_der,
        extra_certs_der,
        now_unix,
    )
}

#[cfg(test)]
#[path = "limits_tests.rs"]
mod limits_tests;
