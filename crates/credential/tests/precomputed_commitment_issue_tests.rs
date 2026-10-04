// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Exercises issuance from an independently approved commitment root.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crypto_core::Algorithm as CryptoAlgorithm;
use crypto_dispatch::generate_keypair;
use reallyme_credential::committed::{
    error::VcError,
    issue::IssueInput,
    model::{
        AssuranceLevel, ClaimsCommitment, CommitmentLimits, CredentialAlgorithm, CredentialKind,
        CredentialStatus, CredentialSubject, DomainTags, HolderBinding, KeyAssurance, KeyReference,
        PartyReference, PublicKeyRef, PublicKeyRepresentation, RawPublicKeySerialization,
        StatusPurpose,
    },
    precomputed_commitment::issue_credential_with_precomputed_commitment,
    proof_binding::issue_credential_proof_binding,
    verify::verify_credential,
};
use reallyme_credential::DispatchCredentialIssuerSigner;

fn p256_key(reference: &str, public_key: &[u8]) -> PublicKeyRef {
    let serialization = if public_key.len() == 33 {
        RawPublicKeySerialization::Sec1Compressed
    } else {
        assert_eq!(public_key.len(), 65);
        RawPublicKeySerialization::Sec1Uncompressed
    };
    PublicKeyRef {
        alg: CredentialAlgorithm::P256,
        reference: KeyReference::DidVerificationMethod(reference.to_owned()),
        public_key: PublicKeyRepresentation::Raw {
            serialization,
            bytes: public_key.to_vec(),
        },
        assurance: KeyAssurance::None,
    }
}

fn input(issuer_key: PublicKeyRef, holder_key: PublicKeyRef) -> IssueInput {
    IssueInput {
        kind: CredentialKind::Pid,
        profile_id: "common-root-test".to_owned(),
        assurance: AssuranceLevel::Substantial,
        issuer_reference: PartyReference::Did("did:test:issuer".to_owned()),
        issuer_verification_key: issuer_key,
        issuer_country: "US".to_owned(),
        valid_from: 1_700_000_000,
        valid_until: 1_800_000_000,
        status: CredentialStatus {
            status_list_url: "https://example.com/status".to_owned(),
            status_list_id: [3_u8; 32],
            status_list_index: 7,
            purpose: StatusPurpose::Revocation,
        },
        subject: CredentialSubject {
            subject_reference: PartyReference::Did("did:test:holder".to_owned()),
            holder_binding: HolderBinding::CryptographicKey(holder_key),
        },
        claimset_id: "common-root-test".to_owned(),
        domain_tags: DomainTags {
            clm: "CLM1".to_owned(),
            leaf: "LEAF1".to_owned(),
            node: "NODE1".to_owned(),
        },
        limits: CommitmentLimits {
            max_value_len: 64,
            salt_len: 16,
        },
        qeaa_compliance: None,
    }
}

fn commitment(root: [u8; 32]) -> ClaimsCommitment {
    ClaimsCommitment {
        merkle_root: root.to_vec(),
        claimset_id: "common-root-test".to_owned(),
        hash_alg: "sha-256".to_owned(),
        value_encoding: "RM-ZK-RAW-V1".to_owned(),
        domain_tags: DomainTags {
            clm: "CLM1".to_owned(),
            leaf: "LEAF1".to_owned(),
            node: "NODE1".to_owned(),
        },
        limits: CommitmentLimits {
            max_value_len: 64,
            salt_len: 16,
        },
    }
}

#[test]
fn signs_the_precomputed_root_and_status_without_reissuing_the_general_ssi_tree() {
    let (issuer_public, issuer_private) = generate_keypair(CryptoAlgorithm::P256).unwrap();
    let (holder_public, _) = generate_keypair(CryptoAlgorithm::P256).unwrap();
    let issuer_key = p256_key("did:test:issuer#key-1", &issuer_public);
    let holder_key = p256_key("did:test:holder#key-1", &holder_public);
    let signer = DispatchCredentialIssuerSigner {
        private_key: &issuer_private,
        verification_key: &issuer_key,
    };
    let root = [0x47_u8; 32];
    let mut issued = issue_credential_with_precomputed_commitment(
        input(issuer_key.clone(), holder_key),
        commitment(root),
        &signer,
    )
    .unwrap();
    assert_eq!(issued.proof_binding.claims_root, root);
    assert_eq!(issued.envelope.claims_commitment.merkle_root, root);
    assert_eq!(issued.envelope.status.status_list_index, 7);
    verify_credential(
        &issued.envelope,
        CryptoAlgorithm::P256,
        &issuer_public,
        None,
    )
    .unwrap();

    *issued
        .envelope
        .claims_commitment
        .merkle_root
        .first_mut()
        .expect("test commitment root is nonempty") ^= 1;
    assert!(issue_credential_proof_binding(&issued.envelope, &signer).is_err());
    *issued
        .envelope
        .claims_commitment
        .merkle_root
        .first_mut()
        .expect("test commitment root is nonempty") ^= 1;
    issued.envelope.status.status_list_index += 1;
    assert!(issue_credential_proof_binding(&issued.envelope, &signer).is_err());
}

#[test]
fn rejects_unapproved_shape_and_wrong_signing_key() {
    let (issuer_public, issuer_private) = generate_keypair(CryptoAlgorithm::P256).unwrap();
    let (holder_public, _) = generate_keypair(CryptoAlgorithm::P256).unwrap();
    let (wrong_public, wrong_private) = generate_keypair(CryptoAlgorithm::P256).unwrap();
    let issuer_key = p256_key("did:test:issuer#key-1", &issuer_public);
    let holder_key = p256_key("did:test:holder#key-1", &holder_public);
    let signer = DispatchCredentialIssuerSigner {
        private_key: &issuer_private,
        verification_key: &issuer_key,
    };
    let wrong_key = p256_key("did:test:wrong#key-1", &wrong_public);
    let wrong_signer = DispatchCredentialIssuerSigner {
        private_key: &wrong_private,
        verification_key: &wrong_key,
    };
    let falsely_identified_signer = DispatchCredentialIssuerSigner {
        private_key: &wrong_private,
        verification_key: &issuer_key,
    };

    let invalid_root = issue_credential_with_precomputed_commitment(
        input(issuer_key.clone(), holder_key.clone()),
        commitment([0_u8; 32]),
        &signer,
    );
    assert!(matches!(invalid_root, Err(VcError::InvalidCredential)));

    let wrong_signer_result = issue_credential_with_precomputed_commitment(
        input(issuer_key.clone(), holder_key.clone()),
        commitment([7_u8; 32]),
        &wrong_signer,
    );
    assert!(matches!(
        wrong_signer_result,
        Err(VcError::InvalidCredential)
    ));

    let false_key_result = issue_credential_with_precomputed_commitment(
        input(issuer_key.clone(), holder_key.clone()),
        commitment([7_u8; 32]),
        &falsely_identified_signer,
    );
    assert!(matches!(
        false_key_result,
        Err(VcError::ProofBindingSignatureInvalid)
    ));

    let mut short_root = commitment([7_u8; 32]);
    short_root.merkle_root.pop();
    let short_root_result = issue_credential_with_precomputed_commitment(
        input(issuer_key.clone(), holder_key.clone()),
        short_root,
        &signer,
    );
    assert!(matches!(short_root_result, Err(VcError::InvalidCredential)));

    let mut wrong_claimset = commitment([7_u8; 32]);
    wrong_claimset.claimset_id = "different".to_owned();
    let wrong_claimset_result = issue_credential_with_precomputed_commitment(
        input(issuer_key.clone(), holder_key),
        wrong_claimset,
        &signer,
    );
    assert!(matches!(
        wrong_claimset_result,
        Err(VcError::InvalidCredential)
    ));
}
