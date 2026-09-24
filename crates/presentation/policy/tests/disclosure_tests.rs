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
//! Tests for VP policy disclosure extraction.

use identity_credential_claims_core::DisclosureMode;
use identity_presentation_vp_policy::extract_disclosed_claims;

use identity_presentation_vp_core::model::{
    ClaimDisclosure, CredentialReference, CredentialStatusRef, DisclosureMode as ZkMode,
    Presentation, PresentationFreshness, SdJwtVcPresentation, StatusPurpose, ZkPresentation,
    ZkProof,
};

use std::collections::BTreeMap;

#[test]
fn extracts_from_sd_jwt_presentation() {
    // Disclosure JSON matches the current SD-JWT disclosure array encoding:
    // [salt_b64, claim_path, value_b64, index, merkle_path[]]
    let disclosure =
        codec_base64url::bytes_to_base64url(br#"["c2FsdA","/claims/age","NDI=",0,[]]"#);

    let pres = Presentation::SdJwtVc(Box::new(SdJwtVcPresentation {
        sd_jwt: "dummy".into(),
        disclosures: vec![disclosure],
        kb_jwt: None,
        vct: None,
        envelope_hash: None,
    }));

    let out = extract_disclosed_claims(&pres).unwrap();
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].claim_path, "/claims/age");
    assert_eq!(out[0].mode, DisclosureMode::Reveal);
}

#[test]
fn extracts_from_zk_presentation() {
    let zk = ZkPresentation {
        freshness: PresentationFreshness {
            challenge: [1u8; 32],
            audience_hash: [2u8; 32],
            expiry_unix: 1_800_000_000,
        },
        credential: CredentialReference {
            envelope_hash: [7u8; 32],
            issuer_did: "did:test:issuer".into(),
            status: CredentialStatusRef {
                status_list_url: "https://example.com/status".into(),
                status_list_id: [0u8; 32],
                status_list_index: 0,
                purpose: StatusPurpose::Revocation,
            },
        },
        disclosures: vec![ClaimDisclosure {
            claim_path: "/claims/age".into(),
            mode: ZkMode::Gte,
            revealed_value: None,
            threshold: Some(18),
            range: None,
            set: None,
        }],
        zk_proof: ZkProof {
            circuit_id: "rm-zk-vc-base-v1".into(),
            circuit_version: "1.0.0".into(),
            vk_id: "vk".into(),
            proof_bytes: vec![1, 2, 3],
            public_inputs: BTreeMap::new(),
            proof_suite: identity_presentation_vp_core::model::ZkProofSuite::BarretenbergUltraHonkKeccakZkNoIpa,
            artifact_manifest_sha256: [9_u8; 32],
        },
        qeaa: None,
    };

    let pres = Presentation::Zk(Box::new(zk));

    let out = extract_disclosed_claims(&pres).unwrap();
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].claim_path, "/claims/age");
    assert_eq!(out[0].mode, DisclosureMode::Gte);
}
