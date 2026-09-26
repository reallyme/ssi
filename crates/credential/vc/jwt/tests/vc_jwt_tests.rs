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
//! Tests for JWT VC envelope helpers.

use std::collections::BTreeMap;

use envelopes_jwt::jwt::encode_signed_jwt;
use identity_vc_jwt::{
    decode_verify_vc_jwt, encode_vc_jwt, VcJwtError, VcJwtPayload, VcJwtVerificationOptions,
    MAX_VC_JWT_CLOCK_SKEW_SECONDS,
};
use reallyme_credential::committed::issue::{issue_credential, IssueInput, OsSaltRng};
use reallyme_credential::committed::model::{
    AssuranceLevel, CommitmentLimits, CredentialAlgorithm, CredentialKind, CredentialStatus,
    CredentialSubject, DomainTags, HolderBinding, KeyAssurance, KeyReference, PartyReference,
    PublicKeyRef, PublicKeyRepresentation, RawPublicKeySerialization, StatusPurpose,
};
use reallyme_credential::committed::signed_envelope::decode_signed_envelope_cbor;

use codec_base64url::bytes_to_base64url;
use crypto_core::Algorithm as CryptoAlgorithm;
use crypto_dispatch::{generate_keypair, verify};
use envelopes_jwk::{Jwk, OkpJwk};

fn base_input() -> IssueInput {
    IssueInput {
        kind: CredentialKind::Pid,
        profile_id: "claims-v1".into(),
        assurance: AssuranceLevel::Substantial,
        issuer_reference: PartyReference::Did("did:test:issuer".into()),
        issuer_verification_key: ed25519_key("did:test:issuer#key-1", vec![2; 32]),
        issuer_country: "EU".into(),
        valid_from: 1_700_000_000,
        valid_until: 1_800_000_000,
        status: CredentialStatus {
            status_list_url: "https://example.com/status".into(),
            status_list_id: [0u8; 32],
            status_list_index: 0,
            purpose: StatusPurpose::Revocation,
        },
        subject: CredentialSubject {
            subject_reference: PartyReference::Did("did:test:subject".into()),
            holder_binding: HolderBinding::CryptographicKey(ed25519_key(
                "did:test:subject#key-1",
                vec![1; 32],
            )),
        },
        claimset_id: "claims-v1".into(),
        domain_tags: DomainTags {
            clm: "CLM1".into(),
            leaf: "LEAF1".into(),
            node: "NODE1".into(),
        },
        limits: CommitmentLimits {
            max_value_len: 64,
            salt_len: 16,
        },
        qeaa_compliance: None,
    }
}

const NOW_UNIX: u64 = 1_750_000_000;
const CLOCK_SKEW_SECONDS: u64 = 60;

fn options_at(now_unix: u64) -> VcJwtVerificationOptions {
    VcJwtVerificationOptions {
        now_unix,
        clock_skew_seconds: CLOCK_SKEW_SECONDS,
    }
}

struct IssuerKey {
    public: Vec<u8>,
    private: Vec<u8>,
    jwk: Jwk,
}

fn issuer_key() -> IssuerKey {
    let (public, private) = generate_keypair(CryptoAlgorithm::Ed25519).unwrap();
    let jwk = Jwk::Okp(OkpJwk {
        kty: "OKP".into(),
        crv: "Ed25519".into(),
        x: bytes_to_base64url(&public),
        alg: Some("EdDSA".into()),
        kid: Some("kid-1".into()),
        use_: None,
    });
    IssuerKey {
        public,
        private: private.to_vec(),
        jwk,
    }
}

fn valid_payload() -> VcJwtPayload {
    VcJwtPayload {
        iss: "did:test:issuer".into(),
        sub: "did:test:subject".into(),
        nbf: Some(1_700_000_000),
        exp: Some(1_800_000_000),
        iat: None,
        jti: None,
        vc_se: bytes_to_base64url(b"signed-envelope-cbor"),
        vc_proto: None,
    }
}

fn sign(payload: &VcJwtPayload, key: &IssuerKey) -> String {
    encode_signed_jwt(payload, &key.jwk, &key.private).unwrap()
}

fn ed25519_key(did_url: &str, bytes: Vec<u8>) -> PublicKeyRef {
    PublicKeyRef {
        alg: CredentialAlgorithm::Ed25519,
        reference: KeyReference::DidVerificationMethod(did_url.into()),
        public_key: PublicKeyRepresentation::Raw {
            serialization: RawPublicKeySerialization::FixedWidth,
            bytes,
        },
        assurance: KeyAssurance::None,
    }
}

#[test]
fn vc_jwt_carries_signed_envelope_and_verifies() {
    let (issuer_pub, issuer_priv) = generate_keypair(CryptoAlgorithm::Ed25519).unwrap();

    // Minimal issuer JWK (must match the envelopes-jwk shape)
    // Use a JWK builder when available; otherwise adapt to local JWK constructors.
    let issuer_jwk = Jwk::Okp(OkpJwk {
        kty: "OKP".into(),
        crv: "Ed25519".into(),
        x: bytes_to_base64url(&issuer_pub),
        alg: Some("EdDSA".into()),
        kid: Some("kid-1".into()),
        use_: None,
    });

    let mut rng = OsSaltRng;

    let mut claims = BTreeMap::new();
    claims.insert("email".into(), serde_json::json!("alice@example.com"));

    let issued = issue_credential(
        base_input(),
        &claims,
        CryptoAlgorithm::Ed25519,
        &issuer_priv,
        &mut rng,
    )
    .unwrap();

    let jwt = encode_vc_jwt(
        &issued.envelope,
        "did:test:issuer",
        "did:test:subject",
        &issuer_jwk,
        &issuer_priv,
        None,
    )
    .unwrap();

    let (_payload, se_bytes) =
        decode_verify_vc_jwt(&jwt, &issuer_jwk, &issuer_pub, &options_at(NOW_UNIX)).unwrap();

    // Verify the signed envelope wrapper too
    let (canon, sig) = decode_signed_envelope_cbor(&se_bytes).unwrap();

    verify(CryptoAlgorithm::Ed25519, &issuer_pub, &canon, &sig.raw_rs).unwrap();
}

#[test]
fn vc_jwt_accepts_claims_inside_validity_window() {
    let key = issuer_key();
    let jwt = sign(&valid_payload(), &key);

    let (_payload, se_bytes) =
        decode_verify_vc_jwt(&jwt, &key.jwk, &key.public, &options_at(NOW_UNIX)).unwrap();

    assert_eq!(se_bytes, b"signed-envelope-cbor");
}

#[test]
fn vc_jwt_rejects_expired_credential() {
    let key = issuer_key();
    let jwt = sign(&valid_payload(), &key);

    let error = decode_verify_vc_jwt(
        &jwt,
        &key.jwk,
        &key.public,
        &options_at(1_800_000_000 + CLOCK_SKEW_SECONDS),
    )
    .unwrap_err();

    assert!(matches!(error, VcJwtError::CredentialExpired));
}

#[test]
fn vc_jwt_accepts_expiry_within_clock_skew() {
    let key = issuer_key();
    let jwt = sign(&valid_payload(), &key);

    decode_verify_vc_jwt(
        &jwt,
        &key.jwk,
        &key.public,
        &options_at(1_800_000_000 + CLOCK_SKEW_SECONDS - 1),
    )
    .unwrap();
}

#[test]
fn vc_jwt_rejects_not_yet_valid_credential() {
    let key = issuer_key();
    let jwt = sign(&valid_payload(), &key);

    let error = decode_verify_vc_jwt(
        &jwt,
        &key.jwk,
        &key.public,
        &options_at(1_700_000_000 - CLOCK_SKEW_SECONDS - 1),
    )
    .unwrap_err();

    assert!(matches!(error, VcJwtError::CredentialNotYetValid));
}

#[test]
fn vc_jwt_rejects_future_issued_at() {
    let key = issuer_key();
    let payload = VcJwtPayload {
        iat: Some(1_750_000_000 + 61),
        ..valid_payload()
    };
    let jwt = sign(&payload, &key);

    let error =
        decode_verify_vc_jwt(&jwt, &key.jwk, &key.public, &options_at(NOW_UNIX)).unwrap_err();

    assert!(matches!(error, VcJwtError::InvalidTemporalClaim));
}

#[test]
fn vc_jwt_rejects_negative_and_inverted_numeric_dates() {
    let key = issuer_key();
    let cases = [
        VcJwtPayload {
            nbf: Some(-1),
            ..valid_payload()
        },
        VcJwtPayload {
            nbf: None,
            exp: Some(-1),
            ..valid_payload()
        },
        VcJwtPayload {
            iat: Some(-1),
            ..valid_payload()
        },
        VcJwtPayload {
            nbf: Some(1_760_000_000),
            exp: Some(1_760_000_000),
            ..valid_payload()
        },
    ];

    for payload in cases {
        let jwt = sign(&payload, &key);
        let error =
            decode_verify_vc_jwt(&jwt, &key.jwk, &key.public, &options_at(NOW_UNIX)).unwrap_err();
        assert!(matches!(error, VcJwtError::InvalidTemporalClaim));
    }
}

#[test]
fn vc_jwt_rejects_invalid_verification_options() {
    let key = issuer_key();
    let jwt = sign(&valid_payload(), &key);
    let cases = [
        VcJwtVerificationOptions {
            now_unix: 0,
            clock_skew_seconds: CLOCK_SKEW_SECONDS,
        },
        VcJwtVerificationOptions {
            now_unix: NOW_UNIX,
            clock_skew_seconds: MAX_VC_JWT_CLOCK_SKEW_SECONDS + 1,
        },
        VcJwtVerificationOptions {
            now_unix: u64::MAX,
            clock_skew_seconds: 1,
        },
    ];

    for case in cases {
        let error = decode_verify_vc_jwt(&jwt, &key.jwk, &key.public, &case).unwrap_err();
        assert!(matches!(error, VcJwtError::InvalidVerificationTime));
    }
}
