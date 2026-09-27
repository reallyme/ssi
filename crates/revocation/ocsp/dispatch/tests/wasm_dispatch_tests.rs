// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Wasm runtime regressions for fail-closed OCSP provider dispatch.

#![cfg(target_arch = "wasm32")]

use identity_revocation_ocsp_core::OcspError;
use identity_revocation_ocsp_dispatch::parse_ocsp_response_der;
use wasm_bindgen_test::wasm_bindgen_test;

#[wasm_bindgen_test]
fn wasm_provider_cannot_convert_host_assertions_into_verified_ocsp_evidence() {
    let error = parse_ocsp_response_der(&[1], &[2], &[3], &[], 1)
        .expect_err("the Wasm lane must fail closed until it verifies OCSP DER internally");
    assert_eq!(error, OcspError::Unsupported);
}
