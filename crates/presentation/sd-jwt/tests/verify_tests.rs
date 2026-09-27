// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::print_stderr
)]
//! Tests for SD-JWT VP verification.

fn copy_sd_jwt_presentation(
    presentation: &identity_presentation_vp_core::model::SdJwtVcPresentation,
) -> identity_presentation_vp_core::model::SdJwtVcPresentation {
    identity_presentation_vp_core::model::SdJwtVcPresentation {
        sd_jwt: presentation.sd_jwt.clone(),
        disclosures: presentation.disclosures.clone(),
        kb_jwt: presentation.kb_jwt.clone(),
        vct: presentation.vct.clone(),
        envelope_hash: presentation.envelope_hash,
    }
}

include!("verify_tests/section_01.rs");
include!("verify_tests/section_02.rs");
