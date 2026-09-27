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
    use identity_revocation_core::{StatusCheckError, StatusChecker};
    use identity_revocation_ocsp_core::OcspCertStatus;
    use identity_revocation_ocsp_dispatch::{parse_ocsp_response_der, OcspChecker};

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

        assert!(matches!(parsed.status(), OcspCertStatus::Good));
        assert!(parsed.this_update() > 0);
    }

    #[test]
    fn verified_response_for_same_serial_under_rogue_ca_cannot_match_legitimate_leaf() {
        let response_der = read_fixture("rogue-response.der");
        let rogue_leaf_der = read_fixture("rogue-leaf.der");
        let rogue_issuer_der = read_fixture("rogue-issuer.der");
        let legitimate_leaf_der = read_fixture("leaf.der");
        let now = 1_790_511_360;

        let verified =
            parse_ocsp_response_der(&response_der, &rogue_leaf_der, &rogue_issuer_der, &[], now)
                .expect("rogue-chain fixture is internally valid");
        let rogue_leaf =
            envelopes_x509::parse_cert_der(&rogue_leaf_der).expect("rogue leaf fixture must parse");
        let legitimate_leaf = envelopes_x509::parse_cert_der(&legitimate_leaf_der)
            .expect("legitimate leaf fixture must parse");
        assert_eq!(rogue_leaf.serial, legitimate_leaf.serial);

        let checker = OcspChecker::new(vec![verified]);
        assert_eq!(checker.check(&rogue_leaf, now), Ok(()));
        assert_eq!(
            checker.check(&legitimate_leaf, now),
            Err(StatusCheckError::Unavailable)
        );
    }
}
