// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use identity_presentation_vp_core::model::{Presentation, SdJwtVcPresentation};

use super::presentation_binds_credential;

fn presentation(envelope_hash: Option<[u8; 32]>) -> Presentation {
    Presentation::SdJwtVc(Box::new(SdJwtVcPresentation {
        sd_jwt: "header.payload.signature".to_owned(),
        disclosures: Vec::new(),
        kb_jwt: None,
        vct: Some("urn:example:credential".to_owned()),
        envelope_hash,
    }))
}

#[test]
fn verified_credential_must_match_the_presentation_envelope_hash() {
    let expected = [0x5a; 32];

    assert!(presentation_binds_credential(
        &presentation(Some(expected)),
        expected
    ));
    assert!(!presentation_binds_credential(
        &presentation(Some([0xa5; 32])),
        expected
    ));
    assert!(!presentation_binds_credential(
        &presentation(None),
        expected
    ));
}
