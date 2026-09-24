// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(missing_docs, clippy::unwrap_used)]
//! Test coverage for this crate.
#![cfg(feature = "proto")]

use std::collections::BTreeMap;

use buffa::Message;
use reallyme_credential_claims::{
    claims_commitment_from_proto, claims_commitment_to_proto, registry_from_proto,
    registry_to_proto, subject_private_bundle_from_proto, subject_private_bundle_to_proto,
    validate_subject_private_bundle, ClaimDefinition, ClaimDisclosurePolicy, ClaimOpening,
    ClaimType, ClaimsCommitment, ClaimsRegistry, CommitmentLimits, CredentialAlgorithm,
    DisclosureMode, DomainTags, KeyAssurance, KeyReference, MerkleTreeInfo, PublicKeyRef,
    PublicKeyRepresentation, RawPublicKeySerialization, Signature, SubjectPrivateBundle,
    ENCODING_JCS_UTF8,
};
use reallyme_ssi_proto::generated::proto::identity::credential::v1 as pb;

fn registry() -> ClaimsRegistry {
    let mut claims = BTreeMap::new();
    claims.insert(
        "age".to_owned(),
        ClaimDefinition {
            claim_id: "age".to_owned(),
            claim_type: ClaimType::UnsignedInteger,
            encoding: ENCODING_JCS_UTF8.to_owned(),
            disclosure: ClaimDisclosurePolicy {
                allow_reveal: false,
                predicates: vec![DisclosureMode::Gte, DisclosureMode::Range],
            },
        },
    );
    ClaimsRegistry {
        claimset_id: "eu.pid.v1".to_owned(),
        claims,
    }
}

fn commitment() -> ClaimsCommitment {
    ClaimsCommitment {
        merkle_root: vec![7; 32],
        claimset_id: "eu.pid.v1".to_owned(),
        hash_alg: "sha-256".to_owned(),
        value_encoding: ENCODING_JCS_UTF8.to_owned(),
        domain_tags: DomainTags {
            clm: "CLM1".to_owned(),
            leaf: "LEAF1".to_owned(),
            node: "NODE1".to_owned(),
        },
        limits: CommitmentLimits {
            max_value_len: 1024,
            salt_len: 16,
        },
    }
}

fn private_bundle() -> SubjectPrivateBundle {
    SubjectPrivateBundle {
        holder_key: Some(PublicKeyRef {
            alg: CredentialAlgorithm::Ed25519,
            reference: KeyReference::DidVerificationMethod("did:example:holder#key-1".to_owned()),
            public_key: PublicKeyRepresentation::Raw {
                serialization: RawPublicKeySerialization::FixedWidth,
                bytes: vec![1; 32],
            },
            assurance: KeyAssurance::None,
        }),
        envelope_hash: vec![2; 32],
        issuer_signature: Signature {
            verification_key: PublicKeyRef {
                alg: CredentialAlgorithm::Ed25519,
                reference: KeyReference::DidVerificationMethod(
                    "did:example:issuer#key-1".to_owned(),
                ),
                public_key: PublicKeyRepresentation::Raw {
                    serialization: RawPublicKeySerialization::FixedWidth,
                    bytes: vec![2; 32],
                },
                assurance: KeyAssurance::None,
            },
            raw_rs: vec![3; 64],
        },
        tree: MerkleTreeInfo { depth: 1, count: 1 },
        claims: vec![ClaimOpening {
            claim_path: "/claims/age".to_owned(),
            salt: vec![4; 16],
            value: b"42".to_vec(),
            index: 0,
            merkle_path: vec![vec![5; 32]],
        }],
    }
}

#[test]
fn native_registry_round_trips_through_generated_proto() {
    let native = registry();
    let proto = registry_to_proto(&native).unwrap();
    let encoded = proto.encode_to_vec();
    let decoded = pb::ClaimsRegistry::decode(&mut encoded.as_slice()).unwrap();
    let back = registry_from_proto(&decoded).unwrap();

    assert_eq!(back.claimset_id, "eu.pid.v1");
    assert_eq!(back.claims["age"].claim_type, ClaimType::UnsignedInteger);
    assert_eq!(
        back.claims["age"].disclosure.predicates,
        vec![DisclosureMode::Gte, DisclosureMode::Range]
    );
}

#[test]
fn native_commitment_and_private_bundle_round_trip_through_generated_proto() {
    let native_commitment = commitment();
    let native_bundle = private_bundle();
    validate_subject_private_bundle(&native_commitment, &native_bundle).unwrap();

    let proto_commitment = claims_commitment_to_proto(&native_commitment).unwrap();
    let encoded_commitment = proto_commitment.encode_to_vec();
    let decoded_commitment =
        pb::ClaimsCommitment::decode(&mut encoded_commitment.as_slice()).unwrap();
    let back_commitment = claims_commitment_from_proto(&decoded_commitment).unwrap();

    let proto_bundle = subject_private_bundle_to_proto(&back_commitment, &native_bundle).unwrap();
    let encoded_bundle = proto_bundle.encode_to_vec();
    let decoded_bundle = pb::SubjectPrivateBundle::decode(&mut encoded_bundle.as_slice()).unwrap();
    let back_bundle = subject_private_bundle_from_proto(&back_commitment, &decoded_bundle).unwrap();

    assert_eq!(back_commitment.merkle_root, vec![7; 32]);
    assert_eq!(back_commitment.domain_tags.leaf, "LEAF1");
    assert_eq!(back_bundle.claims.len(), 1);
    assert_eq!(back_bundle.claims[0].claim_path, "/claims/age");
}
