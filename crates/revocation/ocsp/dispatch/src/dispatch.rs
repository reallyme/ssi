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
//! Cargo feature. Native builds use OpenSSL; browser WASM and host-platform
//! builds call their runtime bindings.

use identity_revocation_ocsp_core::{OcspError, ParsedOcspResponse};

#[path = "limits.rs"]
mod limits;

use limits::validate_ocsp_inputs;

#[cfg(all(
    feature = "native",
    not(all(feature = "wasm", target_arch = "wasm32")),
    not(all(
        feature = "apple-platform",
        any(target_os = "ios", target_os = "macos")
    )),
    not(all(feature = "android-platform", target_os = "android"))
))]
#[path = "parse_native.rs"]
mod parse_native;

#[cfg(all(feature = "wasm", target_arch = "wasm32"))]
#[path = "parse_wasm.rs"]
mod parse_wasm;

#[cfg(all(
    feature = "apple-platform",
    any(target_os = "ios", target_os = "macos")
))]
#[path = "parse_apple.rs"]
mod parse_apple;

#[cfg(all(feature = "android-platform", target_os = "android"))]
#[path = "parse_android.rs"]
mod parse_android;

#[cfg(any(
    all(
        feature = "apple-platform",
        any(target_os = "ios", target_os = "macos")
    ),
    all(feature = "android-platform", target_os = "android")
))]
#[path = "parse_host_ffi.rs"]
mod parse_host_ffi;

#[cfg(not(any(
    all(
        feature = "native",
        not(all(feature = "wasm", target_arch = "wasm32")),
        not(all(
            feature = "apple-platform",
            any(target_os = "ios", target_os = "macos")
        )),
        not(all(feature = "android-platform", target_os = "android"))
    ),
    all(feature = "wasm", target_arch = "wasm32"),
    all(
        feature = "apple-platform",
        any(target_os = "ios", target_os = "macos")
    ),
    all(feature = "android-platform", target_os = "android"),
)))]
#[path = "parse_unavailable.rs"]
mod parse_unavailable;

#[cfg(all(
    feature = "native",
    not(all(feature = "wasm", target_arch = "wasm32")),
    not(all(
        feature = "apple-platform",
        any(target_os = "ios", target_os = "macos")
    )),
    not(all(feature = "android-platform", target_os = "android"))
))]
use parse_native as selected_backend;

#[cfg(all(feature = "wasm", target_arch = "wasm32"))]
use parse_wasm as selected_backend;

#[cfg(all(
    feature = "apple-platform",
    any(target_os = "ios", target_os = "macos")
))]
use parse_apple as selected_backend;

#[cfg(all(feature = "android-platform", target_os = "android"))]
use parse_android as selected_backend;

#[cfg(not(any(
    all(
        feature = "native",
        not(all(feature = "wasm", target_arch = "wasm32")),
        not(all(
            feature = "apple-platform",
            any(target_os = "ios", target_os = "macos")
        )),
        not(all(feature = "android-platform", target_os = "android"))
    ),
    all(feature = "wasm", target_arch = "wasm32"),
    all(
        feature = "apple-platform",
        any(target_os = "ios", target_os = "macos")
    ),
    all(feature = "android-platform", target_os = "android"),
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
