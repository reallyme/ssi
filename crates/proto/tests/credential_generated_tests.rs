// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Tests for generated credential protobuf bindings.

#![cfg(feature = "generated")]
#![allow(missing_docs)]

use buffa::{EnumValue, Message, MessageField};
use reallyme_ssi_proto::generated::proto::identity::credential::v1::{
    ClaimDefinition, ClaimDisclosurePolicy, ClaimOpening, ClaimType, ClaimsCommitment,
    ClaimsRegistry, CommitmentLimits, DisclosureMode, DomainTags, KeyAssurance, KeyReference,
    MerkleTreeInfo, PublicKeyMaterial, PublicKeyRef, RawPublicKey, Signature, SubjectPrivateBundle,
};

fn key(did_url: &str, marker: u8) -> PublicKeyRef {
    use reallyme_ssi_proto::generated::proto::identity::credential::v1 as pb;

    PublicKeyRef {
        reference: MessageField::some(KeyReference {
            kind: Some(
                pb::__buffa::oneof::key_reference::Kind::DidVerificationMethod(did_url.to_owned()),
            ),
            ..Default::default()
        }),
        public_key: MessageField::some(PublicKeyMaterial {
            alg: EnumValue::from(pb::Algorithm::Ed25519),
            representation: Some(
                pb::__buffa::oneof::public_key_material::Representation::Raw(Box::new(
                    RawPublicKey {
                        serialization: EnumValue::from(pb::RawPublicKeySerialization::FixedWidth),
                        bytes: vec![marker; 32],
                        ..Default::default()
                    },
                )),
            ),
            ..Default::default()
        }),
        assurance: MessageField::some(KeyAssurance {
            kind: Some(pb::__buffa::oneof::key_assurance::Kind::None(Box::default())),
            ..Default::default()
        }),
        ..Default::default()
    }
}

#[test]
fn credential_claim_registry_proto_round_trips_with_buffa() {
    let mut registry = ClaimsRegistry {
        claimset_id: "eu.pid.v1".to_owned(),
        ..ClaimsRegistry::default()
    };
    registry.claims.insert(
        "age".to_owned(),
        ClaimDefinition {
            claim_id: "age".to_owned(),
            r#type: EnumValue::from(ClaimType::Integer),
            encoding: "JCS-UTF8".to_owned(),
            disclosure: MessageField::some(ClaimDisclosurePolicy {
                allow_reveal: true,
                predicates: vec![
                    EnumValue::from(DisclosureMode::Gte),
                    EnumValue::from(DisclosureMode::Lte),
                ],
                ..ClaimDisclosurePolicy::default()
            }),
            ..ClaimDefinition::default()
        },
    );

    let encoded = registry.encode_to_vec();
    let decoded_result = ClaimsRegistry::decode(&mut encoded.as_slice());
    assert!(decoded_result.is_ok());
    let decoded = match decoded_result {
        Ok(decoded) => decoded,
        Err(_) => return,
    };

    assert_eq!(decoded.claimset_id, "eu.pid.v1");
    let Some(age) = decoded.claims.get("age") else {
        return;
    };
    assert_eq!(age.encoding, "JCS-UTF8");
}

#[test]
fn credential_claim_bundle_proto_round_trips_with_buffa() {
    let bundle = SubjectPrivateBundle {
        holder_key: MessageField::some(key("did:example:holder#key-1", 1)),
        envelope_hash: vec![2; 32],
        issuer_signature: MessageField::some(Signature {
            verification_key: MessageField::some(key("did:example:issuer#key-1", 2)),
            raw_rs: vec![3; 64],
            ..Signature::default()
        }),
        tree: MessageField::some(MerkleTreeInfo {
            depth: 1,
            count: 1,
            ..MerkleTreeInfo::default()
        }),
        claims: vec![ClaimOpening {
            claim_path: "/claims/age".to_owned(),
            salt: vec![4; 16],
            value: b"42".to_vec(),
            index: 0,
            merkle_path: vec![vec![5; 32]],
            ..ClaimOpening::default()
        }],
        ..SubjectPrivateBundle::default()
    };
    let commitment = ClaimsCommitment {
        merkle_root: vec![7; 32],
        claimset_id: "eu.pid.v1".to_owned(),
        hash_alg: "sha-256".to_owned(),
        value_encoding: "JCS-UTF8".to_owned(),
        domain_tags: MessageField::some(DomainTags {
            clm: "CLM1".to_owned(),
            leaf: "LEAF1".to_owned(),
            node: "NODE1".to_owned(),
            ..DomainTags::default()
        }),
        limits: MessageField::some(CommitmentLimits {
            max_value_len: 1024,
            salt_len: 16,
            ..CommitmentLimits::default()
        }),
        ..ClaimsCommitment::default()
    };

    let encoded_bundle = bundle.encode_to_vec();
    let decoded_bundle_result = SubjectPrivateBundle::decode(&mut encoded_bundle.as_slice());
    assert!(decoded_bundle_result.is_ok());
    let decoded_bundle = match decoded_bundle_result {
        Ok(decoded) => decoded,
        Err(_) => return,
    };

    let encoded_commitment = commitment.encode_to_vec();
    let decoded_commitment_result = ClaimsCommitment::decode(&mut encoded_commitment.as_slice());
    assert!(decoded_commitment_result.is_ok());

    assert_eq!(decoded_bundle.claims.len(), 1);
    assert_eq!(decoded_bundle.claims[0].claim_path, "/claims/age");
}

#[test]
fn subject_private_bundle_debug_redacts_openings() {
    const CLAIM_PATH: &str = "/claims/private-value";
    let bundle = SubjectPrivateBundle {
        claims: vec![ClaimOpening {
            claim_path: CLAIM_PATH.to_owned(),
            salt: vec![0xA5_u8; 16],
            value: b"sensitive-value".to_vec(),
            ..ClaimOpening::default()
        }],
        ..SubjectPrivateBundle::default()
    };

    let debug = format!("{bundle:?}");
    assert!(debug.contains("[REDACTED]"));
    assert!(!debug.contains(CLAIM_PATH));
    assert!(!debug.contains("sensitive-value"));
}
