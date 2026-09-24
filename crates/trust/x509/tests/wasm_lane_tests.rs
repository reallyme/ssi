// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(missing_docs, clippy::unwrap_used)]
//! Test coverage for this crate.

#[cfg(feature = "wasm")]
#[test]
fn wasm_lane_reports_xmldsig_unavailable() {
    let err = reallyme_trust_x509::verify_tsl_xml_dsig_wasm_unavailable().unwrap_err();

    assert_eq!(
        err,
        reallyme_trust_x509::X509Error::SignatureFailed(
            reallyme_trust_x509::X509SignatureFailure::XmlDsigUnavailable
        )
    );
}
