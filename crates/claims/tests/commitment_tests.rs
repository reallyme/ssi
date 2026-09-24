// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(missing_docs, clippy::unwrap_used)]
//! Test coverage for this crate.

use std::collections::BTreeMap;

use reallyme_credential_claims::{
    build_claims_commitment, default_commitment_domain_tags, default_commitment_limits,
    verify_claim_opening, verify_subject_private_bundle, ClaimCommitmentBuildInput,
    ClaimDefinition, ClaimDisclosurePolicy, ClaimOpening, ClaimSaltSource, ClaimType, ClaimValue,
    ClaimsError, ClaimsInvalidReason, ClaimsRegistry, CredentialAlgorithm, DisclosureMode,
    KeyAssurance, KeyReference, PublicKeyRef, PublicKeyRepresentation, RawPublicKeySerialization,
    Signature, CLAIM_COMMITMENT_HASH_ALG_SHA256, CLAIM_COMMITMENT_VALUE_ENCODING,
    ENCODING_JCS_UTF8,
};

struct DeterministicSaltSource {
    next: u8,
}

impl ClaimSaltSource for DeterministicSaltSource {
    fn fill_salt(&mut self, claim_path: &str, salt: &mut [u8]) -> Result<(), ClaimsError> {
        let path_len = u8::try_from(claim_path.len() % 251).unwrap();
        for (index, byte) in salt.iter_mut().enumerate() {
            let offset = u8::try_from(index % 251).unwrap();
            *byte = self.next.wrapping_add(path_len).wrapping_add(offset);
        }
        self.next = self.next.wrapping_add(17);
        Ok(())
    }
}

fn definition(claim_id: &str, claim_type: ClaimType) -> ClaimDefinition {
    ClaimDefinition {
        claim_id: claim_id.to_owned(),
        claim_type,
        encoding: ENCODING_JCS_UTF8.to_owned(),
        disclosure: ClaimDisclosurePolicy {
            allow_reveal: true,
            predicates: vec![DisclosureMode::Gte],
        },
    }
}

fn simple_registry() -> ClaimsRegistry {
    let mut claims = BTreeMap::new();
    claims.insert(
        "age".to_owned(),
        definition("age", ClaimType::UnsignedInteger),
    );
    claims.insert(
        "country".to_owned(),
        definition("country", ClaimType::String),
    );
    ClaimsRegistry {
        claimset_id: "claims.commitment.test.v1".to_owned(),
        claims,
    }
}

fn single_registry() -> ClaimsRegistry {
    let mut claims = BTreeMap::new();
    claims.insert(
        "age".to_owned(),
        definition("age", ClaimType::UnsignedInteger),
    );
    ClaimsRegistry {
        claimset_id: "claims.commitment.single.v1".to_owned(),
        claims,
    }
}

fn nested_registry() -> ClaimsRegistry {
    let mut claims = BTreeMap::new();
    claims.insert(
        "children/0/name".to_owned(),
        definition("children/0/name", ClaimType::String),
    );
    ClaimsRegistry {
        claimset_id: "claims.commitment.nested.v1".to_owned(),
        claims,
    }
}

fn simple_payload() -> ClaimValue {
    let mut values = BTreeMap::new();
    values.insert("age".to_owned(), ClaimValue::Unsigned(42));
    values.insert("country".to_owned(), ClaimValue::String("DE".to_owned()));
    ClaimValue::Object(values)
}

fn single_payload() -> ClaimValue {
    let mut values = BTreeMap::new();
    values.insert("age".to_owned(), ClaimValue::Unsigned(42));
    ClaimValue::Object(values)
}

fn nested_payload() -> ClaimValue {
    let mut child = BTreeMap::new();
    child.insert("name".to_owned(), ClaimValue::String("Ada".to_owned()));

    let mut values = BTreeMap::new();
    values.insert(
        "children".to_owned(),
        ClaimValue::Array(vec![ClaimValue::Object(child)]),
    );
    ClaimValue::Object(values)
}

fn holder_key() -> PublicKeyRef {
    PublicKeyRef {
        alg: CredentialAlgorithm::Ed25519,
        reference: KeyReference::DidVerificationMethod("did:example:holder#key-1".to_owned()),
        public_key: PublicKeyRepresentation::Raw {
            serialization: RawPublicKeySerialization::FixedWidth,
            bytes: vec![1; 32],
        },
        assurance: KeyAssurance::None,
    }
}

fn issuer_signature() -> Signature {
    let mut verification_key = holder_key();
    verification_key.reference =
        KeyReference::DidVerificationMethod("did:example:issuer#key-1".to_owned());
    Signature {
        verification_key,
        raw_rs: vec![2; 64],
    }
}

fn build_input<'a>(
    registry: &'a ClaimsRegistry,
    payload: &'a ClaimValue,
) -> ClaimCommitmentBuildInput<'a> {
    ClaimCommitmentBuildInput {
        registry,
        payload,
        holder_key: Some(holder_key()),
        envelope_hash: vec![3; 32],
        issuer_signature: issuer_signature(),
        limits: default_commitment_limits(),
        domain_tags: default_commitment_domain_tags(),
    }
}

fn duplicate_opening(opening: &ClaimOpening) -> ClaimOpening {
    ClaimOpening {
        claim_path: opening.claim_path.clone(),
        salt: opening.salt.clone(),
        value: opening.value.clone(),
        index: opening.index,
        merkle_path: opening.merkle_path.clone(),
    }
}

#[test]
fn builds_and_verifies_claim_commitment_from_normalized_values() {
    let registry = simple_registry();
    let payload = simple_payload();
    let mut salt_source = DeterministicSaltSource { next: 9 };

    let built =
        build_claims_commitment(build_input(&registry, &payload), &mut salt_source).unwrap();

    assert_eq!(built.commitment.hash_alg, CLAIM_COMMITMENT_HASH_ALG_SHA256);
    assert_eq!(
        built.commitment.value_encoding,
        CLAIM_COMMITMENT_VALUE_ENCODING
    );
    assert_eq!(built.bundle.tree.count, 2);
    assert_eq!(built.bundle.tree.depth, 1);
    assert_eq!(built.bundle.claims.len(), 2);
    verify_subject_private_bundle(&built.commitment, &built.bundle).unwrap();
    for opening in &built.bundle.claims {
        verify_claim_opening(&built.commitment, opening).unwrap();
    }
}

#[test]
fn single_claim_commitment_has_empty_authentication_path() {
    let registry = single_registry();
    let payload = single_payload();
    let mut salt_source = DeterministicSaltSource { next: 4 };

    let built =
        build_claims_commitment(build_input(&registry, &payload), &mut salt_source).unwrap();

    assert_eq!(built.bundle.tree.count, 1);
    assert_eq!(built.bundle.tree.depth, 0);
    assert!(built.bundle.claims[0].merkle_path.is_empty());
    verify_subject_private_bundle(&built.commitment, &built.bundle).unwrap();
}

#[test]
fn nested_array_claim_path_is_committed_and_verified() {
    let registry = nested_registry();
    let payload = nested_payload();
    let mut salt_source = DeterministicSaltSource { next: 21 };

    let built =
        build_claims_commitment(build_input(&registry, &payload), &mut salt_source).unwrap();

    assert_eq!(built.bundle.claims[0].claim_path, "/claims/children/0/name");
    verify_subject_private_bundle(&built.commitment, &built.bundle).unwrap();
}

#[test]
fn tampered_opening_value_does_not_verify() {
    let registry = simple_registry();
    let payload = simple_payload();
    let mut salt_source = DeterministicSaltSource { next: 30 };
    let mut built =
        build_claims_commitment(build_input(&registry, &payload), &mut salt_source).unwrap();

    built.bundle.claims[0].value.push(b'0');

    assert_eq!(
        verify_subject_private_bundle(&built.commitment, &built.bundle),
        Err(ClaimsError::InvalidInput(
            ClaimsInvalidReason::InvalidCommitmentProof
        ))
    );
}

#[test]
fn relabeled_claim_path_does_not_verify() {
    let registry = simple_registry();
    let payload = simple_payload();
    let mut salt_source = DeterministicSaltSource { next: 30 };
    let mut built =
        build_claims_commitment(build_input(&registry, &payload), &mut salt_source).unwrap();

    built.bundle.claims[0].claim_path = "/claims/administrator".to_owned();

    assert_eq!(
        verify_subject_private_bundle(&built.commitment, &built.bundle),
        Err(ClaimsError::InvalidInput(
            ClaimsInvalidReason::InvalidCommitmentProof
        ))
    );
}

#[test]
fn tampered_merkle_path_does_not_verify() {
    let registry = simple_registry();
    let payload = simple_payload();
    let mut salt_source = DeterministicSaltSource { next: 30 };
    let mut built =
        build_claims_commitment(build_input(&registry, &payload), &mut salt_source).unwrap();

    built.bundle.claims[0].merkle_path[0][0] ^= 1;

    assert_eq!(
        verify_subject_private_bundle(&built.commitment, &built.bundle),
        Err(ClaimsError::InvalidInput(
            ClaimsInvalidReason::InvalidCommitmentProof
        ))
    );
}

#[test]
fn duplicate_private_openings_are_rejected() {
    let registry = simple_registry();
    let payload = simple_payload();
    let mut salt_source = DeterministicSaltSource { next: 30 };
    let mut built =
        build_claims_commitment(build_input(&registry, &payload), &mut salt_source).unwrap();

    built.bundle.claims[1] = duplicate_opening(&built.bundle.claims[0]);

    assert_eq!(
        verify_subject_private_bundle(&built.commitment, &built.bundle),
        Err(ClaimsError::InvalidInput(
            ClaimsInvalidReason::InvalidPrivateBundleTree
        ))
    );
}

#[test]
fn inconsistent_private_tree_metadata_is_rejected() {
    let registry = simple_registry();
    let payload = simple_payload();
    let mut salt_source = DeterministicSaltSource { next: 30 };
    let mut built =
        build_claims_commitment(build_input(&registry, &payload), &mut salt_source).unwrap();

    built.bundle.tree.depth = 2;

    assert_eq!(
        verify_subject_private_bundle(&built.commitment, &built.bundle),
        Err(ClaimsError::InvalidInput(
            ClaimsInvalidReason::InvalidPrivateBundleTree
        ))
    );

    let mut built =
        build_claims_commitment(build_input(&registry, &payload), &mut salt_source).unwrap();
    built.bundle.claims[0].index = built.bundle.tree.count;

    assert_eq!(
        verify_subject_private_bundle(&built.commitment, &built.bundle),
        Err(ClaimsError::InvalidInput(
            ClaimsInvalidReason::InvalidPrivateBundleTree
        ))
    );
}

#[test]
fn unsupported_commitment_encoding_is_rejected_by_verifier() {
    let registry = simple_registry();
    let payload = simple_payload();
    let mut salt_source = DeterministicSaltSource { next: 30 };
    let mut built =
        build_claims_commitment(build_input(&registry, &payload), &mut salt_source).unwrap();

    built.commitment.value_encoding = ENCODING_JCS_UTF8.to_owned();

    assert_eq!(
        verify_subject_private_bundle(&built.commitment, &built.bundle),
        Err(ClaimsError::InvalidInput(
            ClaimsInvalidReason::UnsupportedCommitmentEncoding
        ))
    );
}
