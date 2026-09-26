// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use identity_presentation_vp_sd_jwt::{
    build_sd_jwt_presentation, build_sd_jwt_presentation_with_kb_binding, verify_sd_jwt_vp,
    verify_sd_jwt_vp_with_binding, ExpectedKbJwtBinding, KbJwtBindingInput, SdJwtVpError,
};

use reallyme_credential::committed::{
    issue::{issue_credential, OsSaltRng, MAX_COMMITMENT_CLAIMS, MAX_COMMITMENT_VALUE_BYTES},
    model::{
        AssuranceLevel, CommitmentLimits, CredentialAlgorithm, CredentialKind, CredentialStatus,
        CredentialSubject, DomainTags, HolderBinding, KeyAssurance, KeyReference, PartyReference,
        PublicKeyRef, PublicKeyRepresentation, RawPublicKeySerialization, StatusPurpose,
    },
};

use crypto_core::Algorithm;
use crypto_dispatch::generate_keypair;
use reallyme_credential::committed::issue::IssueInput;

use codec_base64url::bytes_to_base64url;
use envelopes_jwk::{Jwk, OkpJwk};
use envelopes_jwt::jwt::{
    encode_signed_jwt, encode_signed_jwt_with_header_options, JwtHeaderEncodeOptions,
};
use reallyme_crypto::sha2::digest as sha2_256_digest;

use std::collections::BTreeMap;

/// Trusted verifier time inside the fixture credential and SD-JWT validity windows.
const TEST_NOW_UNIX: u64 = 1_750_000_000;

// ------------------------------------------------------------
// Helpers
// ------------------------------------------------------------

fn base_input(subject_pub: Vec<u8>) -> IssueInput {
    IssueInput {
        kind: CredentialKind::Pid,
        profile_id: "claims-v1".into(),
        assurance: AssuranceLevel::Substantial,

        issuer_reference: PartyReference::Did("did:test:issuer".into()),
        issuer_verification_key: key("did:test:issuer#key-1", vec![2; 32]),
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
            holder_binding: HolderBinding::CryptographicKey(key(
                "did:test:subject#key-1",
                subject_pub,
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

fn key(did_url: &str, bytes: Vec<u8>) -> PublicKeyRef {
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

/// Build a real issuer-signed SD-JWT VC for this issued credential.
/// (This is test-only scaffolding until `identity/vc/sd-jwt` exists.)
fn issuer_sd_jwt_for_issued(
    issued: &reallyme_credential::committed::issue::IssueResult,
    issuer_jwk: &Jwk,
    issuer_priv: &[u8],
) -> String {
    use envelopes_jwt::jwt::encode_signed_jwt;

    let envelope_hash_b64 =
        codec_base64url::bytes_to_base64url(&issued.subject_bundle.envelope_hash);

    let payload = serde_json::json!({
        "iss": "did:test:issuer",
        "sub": "did:test:subject",
        "nbf": issued.envelope.valid_from,
        "exp": issued.envelope.valid_until,
        "sd_hash": envelope_hash_b64,
        "sd_alg": "sha-256",
    });

    encode_signed_jwt(&payload, issuer_jwk, issuer_priv).unwrap()
}

fn issuer_sd_jwt_for_issued_with_times(
    issued: &reallyme_credential::committed::issue::IssueResult,
    issuer_jwk: &Jwk,
    issuer_priv: &[u8],
    nbf: u64,
    exp: u64,
) -> String {
    let envelope_hash_b64 =
        codec_base64url::bytes_to_base64url(&issued.subject_bundle.envelope_hash);
    let payload = serde_json::json!({
        "iss": "did:test:issuer",
        "sub": "did:test:subject",
        "nbf": nbf,
        "exp": exp,
        "sd_hash": envelope_hash_b64,
        "sd_alg": "sha-256",
    });
    encode_signed_jwt(&payload, issuer_jwk, issuer_priv).unwrap()
}

fn mutate_first_disclosure(
    presentation: &mut identity_presentation_vp_core::model::SdJwtVcPresentation,
    mutate: impl FnOnce(&mut Vec<serde_json::Value>),
) {
    let disclosure = codec_base64url::base64url_to_bytes(&presentation.disclosures[0]).unwrap();
    let mut value: serde_json::Value = serde_json::from_slice(&disclosure).unwrap();
    mutate(value.as_array_mut().unwrap());
    presentation.disclosures[0] = bytes_to_base64url(&serde_json::to_vec(&value).unwrap());
}

// ------------------------------------------------------------
// TESTS
// ------------------------------------------------------------

#[test]
fn sd_jwt_vp_verifies_successfully() {
    // issuer key
    let (issuer_pub, issuer_priv) = generate_keypair(Algorithm::Ed25519).unwrap();

    let issuer_jwk = Jwk::Okp(OkpJwk {
        kty: "OKP".into(),
        crv: "Ed25519".into(),
        x: bytes_to_base64url(&issuer_pub),
        alg: Some("EdDSA".into()),
        kid: Some("issuer-key".into()),
        use_: None,
    });

    // holder key
    let (holder_pub, holder_priv) = generate_keypair(Algorithm::Ed25519).unwrap();

    let holder_jwk = Jwk::Okp(OkpJwk {
        kty: "OKP".into(),
        crv: "Ed25519".into(),
        x: bytes_to_base64url(&holder_pub),
        alg: Some("EdDSA".into()),
        kid: Some("holder-key".into()),
        use_: None,
    });

    // claims
    let mut claims = BTreeMap::new();
    claims.insert("age".into(), serde_json::json!(42));
    claims.insert("country".into(), serde_json::json!("US"));

    let mut rng = OsSaltRng;

    let issued = issue_credential(
        base_input(holder_pub.clone()),
        &claims,
        Algorithm::Ed25519,
        &issuer_priv,
        &mut rng,
    )
    .unwrap();

    // REAL issuer SD-JWT VC
    let issuer_sd_jwt = issuer_sd_jwt_for_issued(&issued, &issuer_jwk, &issuer_priv);

    // Holder builds VP (disclosures + kb_jwt)
    let vp = build_sd_jwt_presentation_with_kb_binding(
        &issued.subject_bundle,
        issuer_sd_jwt.clone(),
        &["/claims/age".into()],
        &holder_jwk,
        &holder_priv,
        KbJwtBindingInput {
            nonce: "nonce-123",
            aud: "verifier.example",
            iat_unix: 1_750_000_000,
        },
    )
    .unwrap();

    // Verify
    let disclosures = verify_sd_jwt_vp_with_binding(
        &vp,
        &issued.envelope,
        &issuer_jwk,
        &issuer_pub,
        Some(&holder_pub),
        ExpectedKbJwtBinding {
            expected_audience: "verifier.example",
            expected_nonce_32: sha2_256_digest(b"nonce-123").into_bytes(),
            now_unix: 1_750_000_000,
            max_iat_age_seconds: 300,
            max_future_iat_skew_seconds: 60,
        },
    )
    .unwrap();

    assert_eq!(disclosures.len(), 1);
    assert_eq!(disclosures[0].claim_path, "/claims/age");
    assert_eq!(disclosures[0].value_jcs, b"42");

    let unbound_verifier_error = verify_sd_jwt_vp(
        &vp,
        &issued.envelope,
        &issuer_jwk,
        &issuer_pub,
        Some(&holder_pub),
        TEST_NOW_UNIX,
    )
    .unwrap_err();
    assert!(matches!(unbound_verifier_error, SdJwtVpError::Crypto));

    let presentation_without_kb = build_sd_jwt_presentation(
        &issued.subject_bundle,
        vp.sd_jwt.clone(),
        &["/claims/age".into()],
    )
    .unwrap();
    let missing_kb_error = verify_sd_jwt_vp_with_binding(
        &presentation_without_kb,
        &issued.envelope,
        &issuer_jwk,
        &issuer_pub,
        Some(&holder_pub),
        ExpectedKbJwtBinding {
            expected_audience: "verifier.example",
            expected_nonce_32: sha2_256_digest(b"nonce-123").into_bytes(),
            now_unix: 1_750_000_000,
            max_iat_age_seconds: 300,
            max_future_iat_skew_seconds: 60,
        },
    )
    .unwrap_err();
    assert!(matches!(missing_kb_error, SdJwtVpError::MissingKeyBinding));

    // Regression for CVE-2026-77456: stripping the KB-JWT from a credential
    // whose signed envelope contains a cryptographic holder key must not turn
    // it into an acceptable bearer presentation at an unbound boundary.
    let stripped_kb_error = verify_sd_jwt_vp(
        &presentation_without_kb,
        &issued.envelope,
        &issuer_jwk,
        &issuer_pub,
        Some(&holder_pub),
        TEST_NOW_UNIX,
    )
    .unwrap_err();
    assert!(matches!(stripped_kb_error, SdJwtVpError::MissingKeyBinding));

    let future_iat = build_sd_jwt_presentation_with_kb_binding(
        &issued.subject_bundle,
        issuer_sd_jwt.clone(),
        &["/claims/age".into()],
        &holder_jwk,
        &holder_priv,
        KbJwtBindingInput {
            nonce: "nonce-123",
            aud: "verifier.example",
            iat_unix: 1_750_000_061,
        },
    )
    .unwrap();
    let future_iat_error = verify_sd_jwt_vp_with_binding(
        &future_iat,
        &issued.envelope,
        &issuer_jwk,
        &issuer_pub,
        Some(&holder_pub),
        ExpectedKbJwtBinding {
            expected_audience: "verifier.example",
            expected_nonce_32: sha2_256_digest(b"nonce-123").into_bytes(),
            now_unix: 1_750_000_000,
            max_iat_age_seconds: 300,
            max_future_iat_skew_seconds: 60,
        },
    )
    .unwrap_err();
    assert!(matches!(future_iat_error, SdJwtVpError::Crypto));

    let stale_iat = build_sd_jwt_presentation_with_kb_binding(
        &issued.subject_bundle,
        issuer_sd_jwt.clone(),
        &["/claims/age".into()],
        &holder_jwk,
        &holder_priv,
        KbJwtBindingInput {
            nonce: "nonce-123",
            aud: "verifier.example",
            iat_unix: 1_749_999_639,
        },
    )
    .unwrap();
    let stale_iat_error = verify_sd_jwt_vp_with_binding(
        &stale_iat,
        &issued.envelope,
        &issuer_jwk,
        &issuer_pub,
        Some(&holder_pub),
        ExpectedKbJwtBinding {
            expected_audience: "verifier.example",
            expected_nonce_32: sha2_256_digest(b"nonce-123").into_bytes(),
            now_unix: 1_750_000_000,
            max_iat_age_seconds: 300,
            max_future_iat_skew_seconds: 60,
        },
    )
    .unwrap_err();
    assert!(matches!(stale_iat_error, SdJwtVpError::Crypto));

    let (attacker_pub, attacker_priv) = generate_keypair(Algorithm::Ed25519).unwrap();
    let attacker_jwk = Jwk::Okp(OkpJwk {
        kty: "OKP".into(),
        crv: "Ed25519".into(),
        x: bytes_to_base64url(&attacker_pub),
        alg: Some("EdDSA".into()),
        kid: Some("attacker-key".into()),
        use_: None,
    });
    let substituted = build_sd_jwt_presentation_with_kb_binding(
        &issued.subject_bundle,
        issuer_sd_jwt,
        &["/claims/age".into()],
        &attacker_jwk,
        &attacker_priv,
        KbJwtBindingInput {
            nonce: "nonce-123",
            aud: "verifier.example",
            iat_unix: 1_750_000_000,
        },
    )
    .unwrap();
    let substituted_key_error = verify_sd_jwt_vp_with_binding(
        &substituted,
        &issued.envelope,
        &issuer_jwk,
        &issuer_pub,
        Some(&attacker_pub),
        ExpectedKbJwtBinding {
            expected_audience: "verifier.example",
            expected_nonce_32: sha2_256_digest(b"nonce-123").into_bytes(),
            now_unix: 1_750_000_000,
            max_iat_age_seconds: 300,
            max_future_iat_skew_seconds: 60,
        },
    )
    .unwrap_err();
    assert!(matches!(substituted_key_error, SdJwtVpError::Crypto));
}

#[test]
fn sd_jwt_vp_fails_if_claim_value_tampered() {
    let (issuer_pub, issuer_priv) = generate_keypair(Algorithm::Ed25519).unwrap();
    let (holder_pub, _) = generate_keypair(Algorithm::Ed25519).unwrap();

    let issuer_jwk = Jwk::Okp(OkpJwk {
        kty: "OKP".into(),
        crv: "Ed25519".into(),
        x: bytes_to_base64url(&issuer_pub),
        alg: Some("EdDSA".into()),
        kid: None,
        use_: None,
    });

    let mut claims = BTreeMap::new();
    claims.insert("age".into(), serde_json::json!(42));

    let mut rng = OsSaltRng;

    let issued = issue_credential(
        base_input(holder_pub.clone()),
        &claims,
        Algorithm::Ed25519,
        &issuer_priv,
        &mut rng,
    )
    .unwrap();

    // REAL issuer SD-JWT VC
    let issuer_sd_jwt = issuer_sd_jwt_for_issued(&issued, &issuer_jwk, &issuer_priv);

    let mut vp = build_sd_jwt_presentation(
        &issued.subject_bundle,
        issuer_sd_jwt,
        &["/claims/age".into()],
    )
    .unwrap();

    // tamper disclosure value (arr[2] = value_b64u)
    let disc = codec_base64url::base64url_to_bytes(&vp.disclosures[0]).unwrap();
    let mut arr: serde_json::Value = serde_json::from_slice(&disc).unwrap();

    arr.as_array_mut().unwrap()[2] = serde_json::json!(bytes_to_base64url(b"43"));

    vp.disclosures[0] = bytes_to_base64url(&serde_json::to_vec(&arr).unwrap());

    let err = verify_sd_jwt_vp(
        &vp,
        &issued.envelope,
        &issuer_jwk,
        &issuer_pub,
        None,
        TEST_NOW_UNIX,
    )
    .unwrap_err();

    assert!(matches!(err, SdJwtVpError::InvalidDisclosure));
}

#[test]
fn sd_jwt_vp_rejects_unbounded_or_inconsistent_merkle_disclosures() {
    let (issuer_pub, issuer_priv) = generate_keypair(Algorithm::Ed25519).unwrap();
    let (holder_pub, _) = generate_keypair(Algorithm::Ed25519).unwrap();
    let issuer_jwk = Jwk::Okp(OkpJwk {
        kty: "OKP".into(),
        crv: "Ed25519".into(),
        x: bytes_to_base64url(&issuer_pub),
        alg: Some("EdDSA".into()),
        kid: None,
        use_: None,
    });
    let mut claims = BTreeMap::new();
    claims.insert("age".into(), serde_json::json!(42));
    claims.insert("country".into(), serde_json::json!("US"));
    let mut rng = OsSaltRng;
    let mut issued = issue_credential(
        base_input(holder_pub),
        &claims,
        Algorithm::Ed25519,
        &issuer_priv,
        &mut rng,
    )
    .unwrap();
    let issuer_sd_jwt = issuer_sd_jwt_for_issued(&issued, &issuer_jwk, &issuer_priv);
    let valid = build_sd_jwt_presentation(
        &issued.subject_bundle,
        issuer_sd_jwt,
        &["/claims/age".into()],
    )
    .unwrap();

    let assert_invalid_disclosure = |presentation| {
        let error = verify_sd_jwt_vp(
            &presentation,
            &issued.envelope,
            &issuer_jwk,
            &issuer_pub,
            None,
            TEST_NOW_UNIX,
        )
        .unwrap_err();
        assert!(matches!(error, SdJwtVpError::InvalidDisclosure));
    };

    let mut short_salt = valid.clone();
    mutate_first_disclosure(&mut short_salt, |parts| {
        parts[0] = serde_json::json!(bytes_to_base64url(&[7_u8]));
    });
    assert_invalid_disclosure(short_salt);

    let mut oversized_path = valid.clone();
    mutate_first_disclosure(&mut oversized_path, |parts| {
        parts[4] = serde_json::json!(vec![bytes_to_base64url(&[0_u8; 32]); 13]);
    });
    assert_invalid_disclosure(oversized_path);

    let mut out_of_range_index = valid.clone();
    mutate_first_disclosure(&mut out_of_range_index, |parts| {
        let depth = parts[4].as_array().unwrap().len();
        parts[3] = serde_json::json!(1_u64.checked_shl(u32::try_from(depth).unwrap()).unwrap());
    });
    assert_invalid_disclosure(out_of_range_index);

    let mut duplicate_index = valid.clone();
    duplicate_index
        .disclosures
        .push(valid.disclosures[0].clone());
    assert_invalid_disclosure(duplicate_index);

    let mut excessive_disclosures = valid.clone();
    excessive_disclosures.disclosures =
        vec![valid.disclosures[0].clone(); MAX_COMMITMENT_CLAIMS + 1];
    let excessive_error = verify_sd_jwt_vp(
        &excessive_disclosures,
        &issued.envelope,
        &issuer_jwk,
        &issuer_pub,
        None,
        TEST_NOW_UNIX,
    )
    .unwrap_err();
    assert!(matches!(excessive_error, SdJwtVpError::InvalidBundle));

    // Any envelope mutation after issuance breaks the issuer signature over
    // the envelope, so it is rejected before Merkle limits are evaluated.
    issued.envelope.claims_commitment.limits.max_value_len = MAX_COMMITMENT_VALUE_BYTES + 1;
    let limit_error = verify_sd_jwt_vp(
        &valid,
        &issued.envelope,
        &issuer_jwk,
        &issuer_pub,
        None,
        TEST_NOW_UNIX,
    )
    .unwrap_err();
    assert!(matches!(limit_error, SdJwtVpError::Crypto));
}

#[test]
fn sd_jwt_vp_fails_if_sd_jwt_is_expired() {
    let (issuer_pub, issuer_priv) = generate_keypair(Algorithm::Ed25519).unwrap();
    let (holder_pub, _) = generate_keypair(Algorithm::Ed25519).unwrap();

    let issuer_jwk = Jwk::Okp(OkpJwk {
        kty: "OKP".into(),
        crv: "Ed25519".into(),
        x: bytes_to_base64url(&issuer_pub),
        alg: Some("EdDSA".into()),
        kid: None,
        use_: None,
    });

    let mut claims = BTreeMap::new();
    claims.insert("age".into(), serde_json::json!(42));

    let mut rng = OsSaltRng;
    let issued = issue_credential(
        base_input(holder_pub.clone()),
        &claims,
        Algorithm::Ed25519,
        &issuer_priv,
        &mut rng,
    )
    .unwrap();

    // Force SD-JWT exp to a timestamp that is definitely in the past.
    let issuer_sd_jwt =
        issuer_sd_jwt_for_issued_with_times(&issued, &issuer_jwk, &issuer_priv, 1, 2);

    let vp = build_sd_jwt_presentation(
        &issued.subject_bundle,
        issuer_sd_jwt,
        &["/claims/age".into()],
    )
    .unwrap();

    let err = verify_sd_jwt_vp(
        &vp,
        &issued.envelope,
        &issuer_jwk,
        &issuer_pub,
        None,
        TEST_NOW_UNIX,
    )
    .unwrap_err();

    assert!(matches!(err, SdJwtVpError::Crypto));
}

#[test]
fn sd_jwt_vp_with_binding_rejects_stale_kb_jwt() {
    let (issuer_pub, issuer_priv) = generate_keypair(Algorithm::Ed25519).unwrap();
    let (holder_pub, holder_priv) = generate_keypair(Algorithm::Ed25519).unwrap();

    let issuer_jwk = Jwk::Okp(OkpJwk {
        kty: "OKP".into(),
        crv: "Ed25519".into(),
        x: bytes_to_base64url(&issuer_pub),
        alg: Some("EdDSA".into()),
        kid: None,
        use_: None,
    });

    let holder_jwk = Jwk::Okp(OkpJwk {
        kty: "OKP".into(),
        crv: "Ed25519".into(),
        x: bytes_to_base64url(&holder_pub),
        alg: Some("EdDSA".into()),
        kid: None,
        use_: None,
    });

    let mut claims = BTreeMap::new();
    claims.insert("age".into(), serde_json::json!(42));

    let mut rng = OsSaltRng;
    let issued = issue_credential(
        base_input(holder_pub.clone()),
        &claims,
        Algorithm::Ed25519,
        &issuer_priv,
        &mut rng,
    )
    .unwrap();

    let issuer_sd_jwt = issuer_sd_jwt_for_issued(&issued, &issuer_jwk, &issuer_priv);
    let mut vp = build_sd_jwt_presentation_with_kb_binding(
        &issued.subject_bundle,
        issuer_sd_jwt,
        &["/claims/age".into()],
        &holder_jwk,
        &holder_priv,
        KbJwtBindingInput {
            nonce: "nonce-123",
            aud: "verifier.example",
            iat_unix: 1_720_000_000,
        },
    )
    .unwrap();

    let nonce = "nonce-123";
    let expected_nonce = sha2_256_digest(nonce.as_bytes()).into_bytes();
    let expected_binding = ExpectedKbJwtBinding {
        expected_audience: "verifier.example",
        expected_nonce_32: expected_nonce,
        now_unix: 1_720_000_000,
        max_iat_age_seconds: 300,
        max_future_iat_skew_seconds: 60,
    };

    // Replace KB-JWT with a token outside the verifier's bounded iat window.
    let payload = serde_json::json!({
        "sd_hash": bytes_to_base64url(issued.subject_bundle.envelope_hash.as_slice()),
        "aud": expected_binding.expected_audience,
        "nonce": nonce,
        "iat": 1_719_999_000,
    });
    let kb_jwt = encode_signed_jwt_with_header_options(
        &payload,
        &holder_jwk,
        &holder_priv,
        &JwtHeaderEncodeOptions::new(Some("kb+jwt".to_owned())),
    )
    .unwrap();
    vp.kb_jwt = Some(kb_jwt);

    let err = verify_sd_jwt_vp_with_binding(
        &vp,
        &issued.envelope,
        &issuer_jwk,
        &issuer_pub,
        Some(&holder_pub),
        expected_binding,
    )
    .unwrap_err();

    assert!(matches!(err, SdJwtVpError::Crypto));
}

fn ed25519_issuer_jwk(public_key: &[u8]) -> Jwk {
    Jwk::Okp(OkpJwk {
        kty: "OKP".into(),
        crv: "Ed25519".into(),
        x: bytes_to_base64url(public_key),
        alg: Some("EdDSA".into()),
        kid: None,
        use_: None,
    })
}

fn issue_age_credential(
    holder_pub: Vec<u8>,
    issuer_priv: &[u8],
    age: u64,
) -> reallyme_credential::committed::issue::IssueResult {
    let mut claims = BTreeMap::new();
    claims.insert("age".into(), serde_json::json!(age));
    let mut rng = OsSaltRng;
    issue_credential(
        base_input(holder_pub),
        &claims,
        Algorithm::Ed25519,
        issuer_priv,
        &mut rng,
    )
    .unwrap()
}

fn holder_binding_for_nonce(nonce: &str) -> ExpectedKbJwtBinding<'static> {
    ExpectedKbJwtBinding {
        expected_audience: "verifier.example",
        expected_nonce_32: sha2_256_digest(nonce.as_bytes()).into_bytes(),
        now_unix: TEST_NOW_UNIX,
        max_iat_age_seconds: 300,
        max_future_iat_skew_seconds: 60,
    }
}
