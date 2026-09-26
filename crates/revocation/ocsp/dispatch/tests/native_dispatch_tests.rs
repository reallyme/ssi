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
//! Tests for native OCSP dispatch selection.

#[cfg(all(feature = "native", not(all(feature = "wasm", target_arch = "wasm32"))))]
mod native {
    use identity_revocation_ocsp_core::OcspCertStatus;
    use identity_revocation_ocsp_dispatch::parse_ocsp_response_der;

    fn read_fixture(name: &str) -> Vec<u8> {
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../openssl/tests/fixtures")
            .join(name);
        std::fs::read(path).unwrap()
    }

    #[test]
    fn dispatch_parses_and_verifies_fixture() {
        let ocsp_der = read_fixture("ocsp.resp.der");
        let leaf_der = read_fixture("leaf.der");
        let issuer_der = read_fixture("issuer.der");
        let root_der = read_fixture("root.der");

        // 2026-01-06T00:00:00Z, inside the fixture validity window.
        let parsed = parse_ocsp_response_der(
            &ocsp_der,
            &leaf_der,
            &issuer_der,
            &[root_der],
            1_767_657_600,
        )
        .expect("fixture must verify");

        assert!(matches!(parsed.status, OcspCertStatus::Good));
        assert_eq!(parsed.signature_valid, Some(true));
        assert_eq!(parsed.responder_authorized, Some(true));
        assert_eq!(parsed.responder_eku_ocsp_signing, Some(true));
        assert!(parsed.this_update > 0);
    }
}
