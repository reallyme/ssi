// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Test coverage for this crate.
#![allow(missing_docs)]
#![allow(clippy::panic)]
#![allow(clippy::unwrap_used)]

use reallyme_vp_core::model::{
    ClaimDisclosure, CredentialReference, CredentialStatusRef, DisclosureMode, Presentation,
    PresentationFreshness, SdJwtVcPresentation, StatusPurpose, ZkPresentation, ZkProof,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}

#[test]
fn sd_jwt_presentation_is_redacted_and_zeroizes() {
    assert_zeroize_on_drop::<Presentation>();
    assert_zeroize_on_drop::<SdJwtVcPresentation>();

    let mut presentation = SdJwtVcPresentation {
        sd_jwt: "eyJhbGciOiJFZERTQSJ9...".into(),
        disclosures: vec![
            "WyJjbGFpbSIsICJjaXR5Il0".into(),
            "WyJjbGFpbSIsICJjb3VudHJ5Il0".into(),
        ],
        kb_jwt: None,
        vct: Some("pid-basic".into()),
        envelope_hash: Some([1u8; 32]),
    };

    let debug = format!("{presentation:?}");
    assert!(debug.contains("<redacted>"));
    assert!(!debug.contains("eyJhbGciOiJFZERTQSJ9"));

    presentation.zeroize();
    assert!(presentation.sd_jwt.is_empty());
    assert!(presentation.disclosures.is_empty());
    assert!(presentation.kb_jwt.is_none());
    assert!(presentation.vct.is_none());
    assert!(presentation.envelope_hash.is_none());
}

#[test]
fn disclosure_mode_enum_is_stable() {
    let modes = vec![
        DisclosureMode::Hidden,
        DisclosureMode::Reveal,
        DisclosureMode::Eq,
        DisclosureMode::Gte,
        DisclosureMode::Lte,
        DisclosureMode::Range,
        DisclosureMode::MemberOfSet,
    ];

    for mode in modes {
        let json = serde_json::to_string(&mode).unwrap();
        let decoded: DisclosureMode = serde_json::from_str(&json).unwrap();
        assert_eq!(mode, decoded);
    }
}

#[test]
fn zk_presentation_is_redacted_and_zeroizes() {
    assert_zeroize_on_drop::<ZkPresentation>();
    assert_zeroize_on_drop::<ZkProof>();

    let mut zk = ZkPresentation {
        freshness: PresentationFreshness {
            challenge: [9u8; 32],
            audience_hash: [7u8; 32],
            expiry_unix: 1_700_000_000,
        },
        credential: CredentialReference {
            envelope_hash: [3u8; 32],
            issuer_did: "did:test:issuer".into(),
            status: CredentialStatusRef {
                status_list_url: "https://example.com/status".into(),
                status_list_id: [0u8; 32],
                status_list_index: 12,
                purpose: StatusPurpose::Revocation,
            },
        },
        disclosures: vec![ClaimDisclosure {
            claim_path: "/claims/age".into(),
            mode: DisclosureMode::Gte,
            revealed_value: None,
            threshold: Some(18),
            range: None,
            set: None,
        }],
        zk_proof: ZkProof {
            circuit_id: "rm-zk-vc-merkle-v1".into(),
            circuit_version: "1.0.0".into(),
            vk_id: "vk-123".into(),
            proof_bytes: vec![1, 2, 3, 4],
            public_inputs: std::collections::BTreeMap::new(),
            proof_suite: reallyme_vp_core::ZkProofSuite::BarretenbergUltraHonkKeccakZkNoIpa,
            artifact_manifest_sha256: [9_u8; 32],
        },
        qeaa: None,
    };

    let debug = format!("{zk:?}");
    assert!(debug.contains("<redacted>"));
    assert!(!debug.contains("/claims/age"));

    zk.zeroize();
    assert_eq!(zk.freshness.challenge, [0_u8; 32]);
    assert!(zk.credential.issuer_did.is_empty());
    assert!(zk.disclosures.is_empty());
    assert!(zk.zk_proof.proof_bytes.is_empty());
}

#[test]
fn presentation_freshness_is_32_bytes() {
    let freshness = PresentationFreshness {
        challenge: [0xaa; 32],
        audience_hash: [0xbb; 32],
        expiry_unix: 123_456_789,
    };

    assert_eq!(freshness.challenge.len(), 32);
    assert_eq!(freshness.audience_hash.len(), 32);
}
