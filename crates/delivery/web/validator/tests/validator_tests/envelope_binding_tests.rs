// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Envelope-binding regression tests for web presentation validation.

use super::*;

#[test]
fn web_rejects_issuer_sd_jwt_that_does_not_commit_to_envelope() {
    let now = 1_720_000_000u64;
    let fixture = issue_fixture(now, true, FixtureHolderBinding::Key, None);
    // An issuer SD-JWT whose sd_hash does not commit to the envelope.
    let unrelated_sd_jwt =
        issuer_sd_jwt(&[7u8; 32], &fixture.issuer_jwk, &fixture.issuer_private_key);
    let Presentation::SdJwtVc(original) = &fixture.presentation else {
        panic!("fixture must be SD-JWT");
    };
    let mut tampered = identity_presentation_vp_core::model::SdJwtVcPresentation {
        sd_jwt: original.sd_jwt.clone(),
        disclosures: original.disclosures.clone(),
        kb_jwt: original.kb_jwt.clone(),
        vct: original.vct.clone(),
        envelope_hash: original.envelope_hash,
    };
    tampered.sd_jwt = unrelated_sd_jwt;
    tampered.envelope_hash = None;
    let tampered = Presentation::SdJwtVc(Box::new(tampered));

    let result = validate_fixture_with(
        &tampered,
        &fixture.envelope,
        &fixture.issuer_public_key,
        "eu.pid.v1",
        None,
        Some(expected_sd_jwt_binding(now)),
        now,
    );
    assert!(is_rejected_with(result, VpPolicyError::ProofInvalid));
}
