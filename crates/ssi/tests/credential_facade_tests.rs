// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(clippy::unwrap_used)]
//! Test coverage for this crate.

use std::collections::BTreeMap;

use reallyme_crypto::core::Algorithm;
use reallyme_crypto::dispatch::generate_keypair;
use reallyme_ssi::claims::core::{
    ClaimDefinition, ClaimDisclosurePolicy, ClaimType, ClaimsRegistry,
};
use reallyme_ssi::credential::api::{
    issue_with_rng, CredentialProfile, CustomProfile, IssueCredentialRequest, IssuerSigning,
};
use reallyme_ssi::credential::committed::{
    issue::OsSaltRng,
    model::{
        AssuranceLevel, CommitmentLimits, CredentialAlgorithm, CredentialKind, CredentialStatus,
        CredentialSubject, DomainTags, HolderBinding, KeyAssurance, KeyReference, PartyReference,
        PublicKeyRef, PublicKeyRepresentation, RawPublicKeySerialization, StatusPurpose,
    },
};

fn test_registry() -> ClaimsRegistry {
    let mut claims = BTreeMap::new();

    claims.insert(
        "family_name".to_owned(),
        ClaimDefinition {
            claim_id: "family_name".to_owned(),
            claim_type: ClaimType::String,
            encoding: "JCS-UTF8".to_owned(),
            disclosure: ClaimDisclosurePolicy {
                allow_reveal: true,
                predicates: Vec::new(),
            },
        },
    );

    ClaimsRegistry {
        claimset_id: "eu.pid.v1".to_owned(),
        claims,
    }
}

fn test_profile() -> CustomProfile {
    CustomProfile {
        claimset_id: "eu.pid.v1".to_owned(),
        kind: CredentialKind::Pid,
        assurance: AssuranceLevel::High,
        domain_tags: DomainTags {
            clm: "CLM1".to_owned(),
            leaf: "LEAF1".to_owned(),
            node: "NODE1".to_owned(),
        },
        limits: CommitmentLimits {
            max_value_len: 128,
            salt_len: 16,
        },
        registry: test_registry(),
        require_qeaa: false,
        required_claim_ids: vec!["family_name".to_owned()],
    }
}

#[test]
fn root_facade_issues_typed_credential_without_parallel_json_transport() {
    let (issuer_public_key, issuer_private_key) = generate_keypair(Algorithm::Ed25519).unwrap();
    let (subject_public_key, _subject_private_key) = generate_keypair(Algorithm::Ed25519).unwrap();

    let mut claims = BTreeMap::new();
    claims.insert("family_name".to_owned(), serde_json::json!("Doe"));

    let request = IssueCredentialRequest {
        profile: CredentialProfile::Custom(test_profile()),
        issuer_reference: PartyReference::Did("did:test:issuer".to_owned()),
        issuer_verification_key: ed25519_key("did:test:issuer#key-1", issuer_public_key),
        issuer_country: "EU".to_owned(),
        subject: CredentialSubject {
            subject_reference: PartyReference::Did("did:test:subject".to_owned()),
            holder_binding: HolderBinding::CryptographicKey(ed25519_key(
                "did:test:subject#key-1",
                subject_public_key,
            )),
        },
        valid_from: 1_700_000_000,
        valid_until: 1_800_000_000,
        status: CredentialStatus {
            status_list_url: "https://issuer.example/status/1".to_owned(),
            status_list_id: [0u8; 32],
            status_list_index: 0,
            purpose: StatusPurpose::Revocation,
        },
        claims,
        qeaa: None,
    };

    let signing = IssuerSigning::new(Algorithm::Ed25519, issuer_private_key.to_vec());
    let mut rng = OsSaltRng;

    let issued = issue_with_rng(request, &signing, &mut rng, 1_700_000_100).unwrap();

    assert_eq!(
        issued.envelope.issuer_reference,
        PartyReference::Did("did:test:issuer".to_owned())
    );
    assert_eq!(issued.envelope.claims_commitment.merkle_root.len(), 32);
    assert_eq!(issued.subject_bundle.claims.len(), 1);
}

fn ed25519_key(did_url: &str, bytes: Vec<u8>) -> PublicKeyRef {
    PublicKeyRef {
        alg: CredentialAlgorithm::Ed25519,
        reference: KeyReference::DidVerificationMethod(did_url.to_owned()),
        public_key: PublicKeyRepresentation::Raw {
            serialization: RawPublicKeySerialization::FixedWidth,
            bytes,
        },
        assurance: KeyAssurance::None,
    }
}
