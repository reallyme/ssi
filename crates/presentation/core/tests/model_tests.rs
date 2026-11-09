// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Test coverage for this crate.
#![allow(missing_docs)]
#![allow(clippy::panic)]
#![allow(clippy::unwrap_used)]

use reallyme_vp_core::model::{
    ClaimDisclosure, CredentialReference, CredentialStatusRef, DisclosureMode, Presentation,
    PresentationFreshness, SdJwtVcPresentation, StatusPurpose, ZkCommonRootPresentation,
    ZkCredentialPresentation, ZkPersonaEvidence, ZkPersonaMode, ZkPersonaPresentation,
    ZkPreparedPersonaEvidence, ZkPresentation, ZkPresentationProofMode, ZkProof,
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

    let mut zk = ZkPresentation::Credential(ZkCredentialPresentation {
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
            circuit_id: "rm-zk-credential-subject-claim-v1".into(),
            circuit_version: "1.0.0".into(),
            vk_id: "vk-123".into(),
            proof_bytes: vec![1, 2, 3, 4],
            public_inputs: std::collections::BTreeMap::new(),
            proof_suite: reallyme_vp_core::ZkProofSuite::BarretenbergUltraHonkKeccakZkNoIpa,
            artifact_manifest_sha256: [9_u8; 32],
        },
        qeaa: None,
    });

    let debug = format!("{zk:?}");
    assert!(debug.contains("<redacted>"));
    assert!(!debug.contains("/claims/age"));

    zk.zeroize();
    let ZkPresentation::Credential(value) = &zk else {
        panic!("the test constructs a credential presentation");
    };
    assert_eq!(value.freshness.challenge, [0_u8; 32]);
    assert!(value.credential.issuer_did.is_empty());
    assert!(value.disclosures.is_empty());
    assert!(value.zk_proof.proof_bytes.is_empty());
}

#[test]
fn persona_and_common_root_packages_are_redacted_and_zeroize() {
    assert_zeroize_on_drop::<ZkPersonaPresentation>();
    assert_zeroize_on_drop::<ZkCommonRootPresentation>();
    let freshness = || PresentationFreshness {
        challenge: [1; 32],
        audience_hash: [2; 32],
        expiry_unix: 1_700_000_000,
    };
    let mut persona = ZkPresentation::Persona(ZkPersonaPresentation {
        freshness: freshness(),
        mode: ZkPersonaMode::Private,
        disclosures: Vec::new(),
        evidence: ZkPersonaEvidence::RequestBound {
            proof_package: vec![1, 2, 3],
        },
    });
    let mut root = ZkPresentation::CommonRoot(ZkCommonRootPresentation {
        freshness: freshness(),
        mode: ZkPersonaMode::Public,
        disclosures: Vec::new(),
        proof_package: vec![4, 5, 6],
    });
    assert_eq!(format!("{persona:?}"), "ZkPresentation(<redacted>)");
    assert_eq!(
        persona.proof_mode(),
        ZkPresentationProofMode::RequestBoundProof
    );
    assert_eq!(format!("{root:?}"), "ZkPresentation(<redacted>)");
    persona.zeroize();
    root.zeroize();
    if let ZkPresentation::Persona(value) = &persona {
        assert!(matches!(
            &value.evidence,
            ZkPersonaEvidence::RequestBound { proof_package } if proof_package.is_empty()
        ));
    } else {
        panic!("the test constructs a persona presentation");
    }
    if let ZkPresentation::CommonRoot(value) = &root {
        assert!(value.proof_package.is_empty());
    } else {
        panic!("the test constructs a common-root presentation");
    }
}

#[test]
fn prepared_persona_has_distinct_proof_mode_and_zeroizes_all_packages() {
    assert_zeroize_on_drop::<ZkPersonaEvidence>();
    assert_zeroize_on_drop::<ZkPreparedPersonaEvidence>();
    let mut presentation = ZkPresentation::Persona(ZkPersonaPresentation {
        freshness: PresentationFreshness {
            challenge: [1; 32],
            audience_hash: [2; 32],
            expiry_unix: 1_700_000_000,
        },
        mode: ZkPersonaMode::Private,
        disclosures: Vec::new(),
        evidence: ZkPersonaEvidence::Prepared(ZkPreparedPersonaEvidence {
            prepared_evidence_package: vec![1; 8],
            current_state_package: vec![2; 8],
            verifier_request: vec![3; 8],
            holder_authentication: vec![4; 8],
            holder_public_key: [5; 64],
            holder_signature: [6; 64],
        }),
    });
    assert_eq!(
        presentation.proof_mode(),
        ZkPresentationProofMode::PreparedProof
    );
    presentation.zeroize();
    let ZkPresentation::Persona(persona) = &presentation else {
        panic!("the test constructs a persona presentation");
    };
    let ZkPersonaEvidence::Prepared(prepared) = &persona.evidence else {
        panic!("the test constructs prepared evidence");
    };
    assert!(prepared.prepared_evidence_package.is_empty());
    assert!(prepared.current_state_package.is_empty());
    assert!(prepared.verifier_request.is_empty());
    assert!(prepared.holder_authentication.is_empty());
    assert_eq!(prepared.holder_public_key, [0; 64]);
    assert_eq!(prepared.holder_signature, [0; 64]);
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
