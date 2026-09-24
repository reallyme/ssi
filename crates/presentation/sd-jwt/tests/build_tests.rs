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
//! Tests for SD-JWT VP construction helpers.

use identity_presentation_vp_sd_jwt::{build_sd_jwt_presentation, SdJwtVpError};

use reallyme_credential::committed::model::{
    ClaimOpening, CredentialAlgorithm, KeyAssurance, KeyReference, MerkleTreeInfo, PublicKeyRef,
    PublicKeyRepresentation, RawPublicKeySerialization, Signature, SubjectPrivateBundle,
};

fn key(did_url: &str, marker: u8) -> PublicKeyRef {
    PublicKeyRef {
        alg: CredentialAlgorithm::Ed25519,
        reference: KeyReference::DidVerificationMethod(did_url.into()),
        public_key: PublicKeyRepresentation::Raw {
            serialization: RawPublicKeySerialization::FixedWidth,
            bytes: vec![marker; 32],
        },
        assurance: KeyAssurance::None,
    }
}

#[test]
fn builds_sd_jwt_presentation_with_disclosures() {
    let bundle = SubjectPrivateBundle {
        holder_key: Some(key("did:test:holder#key-1", 1)),
        envelope_hash: vec![9u8; 32],
        issuer_signature: Signature {
            verification_key: key("did:test:issuer#key-1", 2),
            raw_rs: vec![7u8; 64],
        },
        tree: MerkleTreeInfo { depth: 1, count: 2 },
        claims: vec![
            ClaimOpening {
                claim_path: "/claims/age".into(),
                value: br#"42"#.to_vec(),
                salt: vec![1u8; 16],
                index: 0,
                merkle_path: vec![vec![2u8; 32]],
            },
            ClaimOpening {
                claim_path: "/claims/name".into(),
                value: br#""Alice""#.to_vec(),
                salt: vec![3u8; 16],
                index: 1,
                merkle_path: vec![vec![4u8; 32]],
            },
        ],
    };

    let vp = build_sd_jwt_presentation(
        &bundle,
        "issuer.sd.jwt.compact".to_string(), // issuer-signed SD-JWT VC
        &["/claims/age".into()],
    )
    .unwrap();

    assert_eq!(vp.disclosures.len(), 1);
    assert_eq!(vp.sd_jwt, "issuer.sd.jwt.compact");
    assert_eq!(vp.envelope_hash.unwrap(), [9u8; 32]);
    assert!(vp.kb_jwt.is_none());
}

#[test]
fn rejects_missing_claim() {
    let bundle = SubjectPrivateBundle {
        holder_key: Some(key("did:test:holder#key-1", 1)),
        envelope_hash: vec![0u8; 32],
        issuer_signature: Signature {
            verification_key: key("did:test:issuer#key-1", 2),
            raw_rs: vec![0u8; 64],
        },
        tree: MerkleTreeInfo { depth: 1, count: 1 },
        claims: vec![],
    };

    let err = build_sd_jwt_presentation(
        &bundle,
        "issuer.sd.jwt.compact".to_string(),
        &["/claims/age".into()],
    )
    .unwrap_err();

    assert!(matches!(err, SdJwtVpError::ClaimNotFound));
}
