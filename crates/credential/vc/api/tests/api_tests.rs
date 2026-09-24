// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(
    missing_docs,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::print_stderr
)]
#![cfg(all(feature = "jwt", feature = "ietf-sd-jwt"))]
//! Test coverage for this crate.

use std::collections::BTreeMap;

use crypto_core::Algorithm;
use crypto_dispatch::generate_keypair;

use identity_credential_claims_core::{
    ClaimDefinition, ClaimDisclosurePolicy, ClaimType, ClaimsRegistry,
};

use identity_credential_vc_api::{
    issue_and_encode_with_rng, issue_with_rng, CredentialProfile, CustomProfile,
    IssueCredentialRequest, IssuerSigning, PublicEncoderConfigs, PublicFormat,
};

use reallyme_credential::committed::{
    issue::OsSaltRng,
    model::{
        AssuranceLevel, CommitmentLimits, CredentialAlgorithm, CredentialKind, CredentialStatus,
        CredentialSubject, DomainTags, HolderBinding, KeyAssurance, KeyReference, PartyReference,
        PublicKeyRef, PublicKeyRepresentation, RawPublicKeySerialization,
    },
};

use identity_vc_ietf_sd_jwt::{
    verify_ietf_sd_jwt_vc, verify_me_profile_merkle_binding, IetfSdJwtJwtType,
};
use identity_vc_jwt::decode_verify_vc_jwt;

use codec_base64url::bytes_to_base64url;
use envelopes_jwk::{Jwk, OkpJwk};
use zeroize::Zeroize;

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

fn test_registry() -> ClaimsRegistry {
    let mut claims = BTreeMap::new();

    claims.insert(
        "age".into(),
        ClaimDefinition {
            claim_id: "age".into(),
            claim_type: ClaimType::Integer,
            encoding: "JCS-UTF8".into(),
            disclosure: ClaimDisclosurePolicy {
                allow_reveal: true,
                predicates: vec![],
            },
        },
    );

    claims.insert(
        "family_name".into(),
        ClaimDefinition {
            claim_id: "family_name".into(),
            claim_type: ClaimType::String,
            encoding: "JCS-UTF8".into(),
            disclosure: ClaimDisclosurePolicy {
                allow_reveal: true,
                predicates: vec![],
            },
        },
    );

    ClaimsRegistry {
        claimset_id: "eu.pid.v1".into(),
        claims,
    }
}

fn pid_profile() -> CustomProfile {
    CustomProfile {
        claimset_id: "eu.pid.v1".into(),
        kind: CredentialKind::Pid,
        assurance: AssuranceLevel::High,
        domain_tags: DomainTags {
            clm: "CLM1".into(),
            leaf: "LEAF1".into(),
            node: "NODE1".into(),
        },
        limits: CommitmentLimits {
            max_value_len: 64,
            salt_len: 16,
        },
        registry: test_registry(),
        require_qeaa: false,
        required_claim_ids: vec!["age".into(), "family_name".into()],
    }
}

fn issuer_keys() -> (Vec<u8>, Vec<u8>, Jwk) {
    let (pubkey, privkey) = generate_keypair(Algorithm::Ed25519).unwrap();

    let jwk = Jwk::Okp(OkpJwk {
        kty: "OKP".into(),
        crv: "Ed25519".into(),
        x: bytes_to_base64url(&pubkey),
        alg: Some("EdDSA".into()),
        kid: Some("issuer-key-1".into()),
        use_: None,
    });

    (pubkey, privkey.to_vec(), jwk)
}

fn sample_claims() -> BTreeMap<String, serde_json::Value> {
    let mut claims = BTreeMap::new();
    claims.insert("age".into(), serde_json::json!(42));
    claims.insert("family_name".into(), serde_json::json!("Doe"));
    claims
}

fn sample_issue_request(issuer_pub: Vec<u8>, subject_pub: Vec<u8>) -> IssueCredentialRequest {
    IssueCredentialRequest {
        profile: CredentialProfile::Custom(pid_profile()),

        issuer_reference: PartyReference::Did("did:test:issuer".into()),
        issuer_verification_key: public_key(
            "did:test:issuer#key-1",
            CredentialAlgorithm::Ed25519,
            issuer_pub,
        ),
        issuer_country: "EU".into(),

        subject: CredentialSubject {
            subject_reference: PartyReference::Did("did:test:subject".into()),
            holder_binding: HolderBinding::CryptographicKey(public_key(
                "did:test:subject#key-1",
                CredentialAlgorithm::Ed25519,
                subject_pub,
            )),
        },

        valid_from: 1_700_000_000,
        valid_until: 1_800_000_000,

        status: CredentialStatus {
            status_list_url: "https://example.com/status".into(),
            status_list_id: [0u8; 32],
            status_list_index: 0,
            purpose: reallyme_credential::committed::model::StatusPurpose::Revocation,
        },

        claims: sample_claims(),
        qeaa: None,
    }
}

fn public_key(did_url: &str, alg: CredentialAlgorithm, bytes: Vec<u8>) -> PublicKeyRef {
    PublicKeyRef {
        alg,
        reference: KeyReference::DidVerificationMethod(did_url.into()),
        public_key: PublicKeyRepresentation::Raw {
            serialization: RawPublicKeySerialization::FixedWidth,
            bytes,
        },
        assurance: KeyAssurance::None,
    }
}

#[test]
fn issuance_request_debug_is_privacy_safe_and_zeroization_is_recursive() {
    let mut request = sample_issue_request(vec![0x5A; 32], vec![0xA5; 32]);
    request.claims.insert(
        "contact".into(),
        serde_json::json!({
            "email": "alice.private@example.test",
            "address": ["sensitive-street"]
        }),
    );

    let debug = format!("{request:?}");
    assert!(!debug.contains("did:test:issuer"));
    assert!(!debug.contains("did:test:subject"));
    assert!(!debug.contains("alice.private@example.test"));
    assert!(!debug.contains("sensitive-street"));
    assert!(!debug.contains("https://example.com/status"));

    request.zeroize();

    let CredentialProfile::Custom(profile) = &request.profile;
    assert!(profile.claimset_id.is_empty());
    assert!(profile.registry.claimset_id.is_empty());
    assert!(profile.registry.claims.is_empty());
    assert!(profile.required_claim_ids.is_empty());
    assert!(matches!(
        &request.issuer_reference,
        PartyReference::Did(value) if value.is_empty()
    ));
    assert_eq!(
        request.issuer_verification_key.alg,
        CredentialAlgorithm::Unspecified
    );
    assert!(request.issuer_country.is_empty());
    assert!(matches!(
        &request.subject.subject_reference,
        PartyReference::Did(value) if value.is_empty()
    ));
    assert!(matches!(
        &request.subject.holder_binding,
        HolderBinding::CryptographicKey(key)
            if key.alg == CredentialAlgorithm::Unspecified
    ));
    assert!(request.status.status_list_url.is_empty());
    assert_eq!(request.status.status_list_id, [0_u8; 32]);
    assert!(request.claims.is_empty());
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn issues_merkle_credential_and_encodes_standardized_formats() {
    let now = 1_700_000_000u64;

    // issuer
    let (issuer_pub, issuer_priv, issuer_jwk) = issuer_keys();

    let signing = IssuerSigning::new(Algorithm::Ed25519, issuer_priv.clone());

    // subject
    let (subject_pub, _subject_priv) = generate_keypair(Algorithm::Ed25519).unwrap();

    let mut rng = OsSaltRng;

    // ---------------------------------------------------------------------
    // 1) Canonical issuance (no encoding)
    // ---------------------------------------------------------------------
    let issued = issue_with_rng(
        sample_issue_request(issuer_pub.clone(), subject_pub.clone()),
        &signing,
        &mut rng,
        now,
    )
    .unwrap();

    assert_eq!(issued.subject_bundle.claims.len(), 2);
    assert_eq!(issued.envelope.claims_commitment.merkle_root.len(), 32);

    // ---------------------------------------------------------------------
    // 2) JWT-VC
    // ---------------------------------------------------------------------
    let jwt_out = issue_and_encode_with_rng(
        sample_issue_request(issuer_pub.clone(), subject_pub.clone()),
        &signing,
        &mut rng,
        now,
        PublicFormat::JwtVc,
        PublicEncoderConfigs {
            jwt: Some(&identity_credential_vc_api::JwtIssuerConfig {
                issuer_did: "did:test:issuer".into(),
                issuer_jwk: issuer_jwk.clone(),
            }),
            ietf_sd_jwt: None,
        },
    )
    .unwrap();

    let jwt_str = core::str::from_utf8(&jwt_out.public_bytes).unwrap();

    let (_payload, vc_bytes) = decode_verify_vc_jwt(jwt_str, &issuer_jwk, &issuer_pub).unwrap();

    assert!(!vc_bytes.is_empty());

    // ---------------------------------------------------------------------
    // 3) IETF SD-JWT VC
    // ---------------------------------------------------------------------
    let ietf_sd_jwt_out = issue_and_encode_with_rng(
        sample_issue_request(issuer_pub.clone(), subject_pub),
        &signing,
        &mut rng,
        now,
        PublicFormat::IetfSdJwtVc,
        PublicEncoderConfigs {
            jwt: None,
            ietf_sd_jwt: Some(&identity_credential_vc_api::IetfSdJwtIssuerConfig {
                issuer_jwk: issuer_jwk.clone(),
                jwt_type: IetfSdJwtJwtType::DcSdJwt,
                include_me_profile_merkle_binding: true,
                salt_len: 16,
            }),
        },
    )
    .unwrap();

    let ietf_sd_jwt_str = core::str::from_utf8(&ietf_sd_jwt_out.public_bytes).unwrap();
    assert!(ietf_sd_jwt_str.contains('~'));

    let verified = verify_ietf_sd_jwt_vc(ietf_sd_jwt_str, &issuer_jwk, &issuer_pub).unwrap();
    assert_eq!(verified.disclosed_claims["age"], serde_json::json!(42));
    assert_eq!(
        verified.disclosed_claims["family_name"],
        serde_json::json!("Doe")
    );

    let payload = verified.payload.as_object().unwrap();
    let binding = verify_me_profile_merkle_binding(
        payload,
        ietf_sd_jwt_out
            .envelope
            .claims_commitment
            .merkle_root
            .as_slice(),
        ietf_sd_jwt_out.envelope.claims_commitment.hash_alg.as_str(),
    )
    .unwrap();
    assert_eq!(
        binding.merkle_root_b64u,
        bytes_to_base64url(
            ietf_sd_jwt_out
                .envelope
                .claims_commitment
                .merkle_root
                .as_slice()
        )
    );
}
