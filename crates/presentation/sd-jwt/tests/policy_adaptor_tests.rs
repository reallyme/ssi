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
//! Tests for SD-JWT VP policy disclosure adaptation.

use identity_credential_claims_core::DisclosureMode;
use identity_presentation_vp_core::model::SdJwtVcPresentation;
use identity_presentation_vp_sd_jwt::extract_disclosed_claims;

#[test]
fn extracts_disclosed_claim_paths() {
    let vp = SdJwtVcPresentation {
        sd_jwt: "dummy".into(),
        disclosures: vec![codec_base64url::bytes_to_base64url(
            br#"["salt","/claims/age","NDI=",0,[]]"#,
        )],
        kb_jwt: None,
        vct: None,
        envelope_hash: None,
    };

    let disclosed = extract_disclosed_claims(&vp).unwrap();

    assert_eq!(disclosed.len(), 1);
    assert_eq!(disclosed[0].claim_path, "/claims/age");
    assert_eq!(disclosed[0].mode, DisclosureMode::Reveal);
}
