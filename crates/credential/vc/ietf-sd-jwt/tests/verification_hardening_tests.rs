// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Negative coverage for temporal, structural, and registered-claim rules.

#![allow(
    missing_docs,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::print_stderr
)]

use codec_base64url::bytes_to_base64url;
use crypto_core::Algorithm;
use crypto_dispatch::generate_keypair;
use crypto_sha2_256::digest as sha2_256_digest;
use envelopes_jwk::{Jwk, OkpJwk};
use envelopes_jwt::jwt::{encode_signed_jwt_with_header_options, JwtHeaderEncodeOptions};
use identity_vc_ietf_sd_jwt::{
    issue_ietf_sd_jwt_vc, issue_rfc9901_sd_jwt, verify_ietf_sd_jwt_vc, verify_rfc9901_sd_jwt,
    IetfSdJwtIssueInput, IetfSdJwtTemporalPolicy, IetfSdJwtVcError, KbJwtVerifyParams,
    Rfc9901IssueInput, SdJwtArtifact, SelectiveDisclosureStrategy,
    MAX_IETF_SD_JWT_CLOCK_SKEW_SECONDS,
};
use serde_json::{json, Map, Value};

const NOW: u64 = 1_738_100_100;
const SALT: &str = "c2FsdHNhbHRzYWx0c2FsdA";

struct Issuer {
    public: Vec<u8>,
    private: Vec<u8>,
    jwk: Jwk,
}

fn issuer() -> Issuer {
    let (public, private) = generate_keypair(Algorithm::Ed25519).expect("keygen");
    let jwk = Jwk::Okp(OkpJwk {
        kty: "OKP".to_owned(),
        crv: "Ed25519".to_owned(),
        x: bytes_to_base64url(&public),
        alg: Some("EdDSA".to_owned()),
        kid: Some("issuer-key-hardening".to_owned()),
        use_: None,
    });
    Issuer {
        public,
        private: private.to_vec(),
        jwk,
    }
}

fn encode_disclosure(elements: &Value) -> (String, String) {
    let encoded = bytes_to_base64url(&serde_json::to_vec(elements).expect("disclosure json"));
    let digest = bytes_to_base64url(sha2_256_digest(encoded.as_bytes()).as_bytes());
    (encoded, digest)
}

fn signed_artifact(issuer: &Issuer, payload: &Value, disclosures: Vec<String>) -> SdJwtArtifact {
    let issuer_signed_jwt = encode_signed_jwt_with_header_options(
        payload,
        &issuer.jwk,
        &issuer.private,
        &JwtHeaderEncodeOptions::new(Some("dc+sd-jwt".to_owned())),
    )
    .expect("issuer JWT");
    SdJwtArtifact {
        issuer_signed_jwt,
        disclosures,
        kb_jwt: None,
        records: Vec::new(),
    }
}

fn verify_error(issuer: &Issuer, artifact: &SdJwtArtifact, now_unix: u64) -> IetfSdJwtVcError {
    verify_rfc9901_sd_jwt(
        artifact,
        &issuer.jwk,
        &issuer.public,
        &IetfSdJwtTemporalPolicy::new(now_unix),
        None,
    )
    .expect_err("verification must fail")
}

fn legacy_error(issuer: &Issuer, artifact: &SdJwtArtifact, now_unix: u64) -> IetfSdJwtVcError {
    let compact = artifact.to_compact().expect("compact");
    verify_ietf_sd_jwt_vc(
        &compact,
        &issuer.jwk,
        &issuer.public,
        &IetfSdJwtTemporalPolicy::new(now_unix),
    )
    .expect_err("legacy verification must fail")
}

#[test]
fn verifiers_enforce_credential_validity_window() {
    let issuer = issuer();
    let artifact = signed_artifact(
        &issuer,
        &json!({"iss": "https://issuer.example", "iat": NOW, "nbf": NOW, "exp": NOW + 600}),
        Vec::new(),
    );
    verify_rfc9901_sd_jwt(
        &artifact,
        &issuer.jwk,
        &issuer.public,
        &IetfSdJwtTemporalPolicy::new(NOW),
        None,
    )
    .expect("credential inside its validity window verifies");

    assert!(matches!(
        verify_error(&issuer, &artifact, NOW + 3_600),
        IetfSdJwtVcError::CredentialExpired
    ));
    assert!(matches!(
        legacy_error(&issuer, &artifact, NOW + 3_600),
        IetfSdJwtVcError::CredentialExpired
    ));
    assert!(matches!(
        verify_error(&issuer, &artifact, NOW - 3_600),
        IetfSdJwtVcError::CredentialNotYetValid
    ));
    assert!(matches!(
        legacy_error(&issuer, &artifact, NOW - 3_600),
        IetfSdJwtVcError::CredentialNotYetValid
    ));

    let malformed = signed_artifact(&issuer, &json!({"exp": "soon"}), Vec::new());
    assert!(matches!(
        verify_error(&issuer, &malformed, NOW),
        IetfSdJwtVcError::InvalidTemporalClaim
    ));
}

#[test]
fn verifiers_reject_unset_or_unbounded_clock_before_signature_work() {
    let issuer = issuer();
    let unsigned = SdJwtArtifact {
        issuer_signed_jwt: "e30.e30.c2ln".to_owned(),
        disclosures: Vec::new(),
        kb_jwt: None,
        records: Vec::new(),
    };
    assert!(matches!(
        verify_error(&issuer, &unsigned, 0),
        IetfSdJwtVcError::InvalidVerificationPolicy
    ));
    let unbounded = IetfSdJwtTemporalPolicy {
        now_unix: NOW,
        clock_skew_seconds: MAX_IETF_SD_JWT_CLOCK_SKEW_SECONDS + 1,
    };
    assert!(matches!(
        verify_ietf_sd_jwt_vc("e30.e30.c2ln~", &issuer.jwk, &issuer.public, &unbounded),
        Err(IetfSdJwtVcError::InvalidVerificationPolicy)
    ));
}

#[test]
fn rfc9901_verifier_rejects_empty_key_binding_expectations_before_signature_work() {
    let issuer = issuer();
    let unsigned = SdJwtArtifact {
        issuer_signed_jwt: "e30.e30.c2ln".to_owned(),
        disclosures: Vec::new(),
        kb_jwt: Some("e30.e30.c2ln".to_owned()),
        records: Vec::new(),
    };
    for (audience, nonce) in [("", "nonce"), ("https://verifier.example", "")] {
        let error = verify_rfc9901_sd_jwt(
            &unsigned,
            &issuer.jwk,
            &issuer.public,
            &IetfSdJwtTemporalPolicy::new(NOW),
            Some(KbJwtVerifyParams {
                holder_jwk: &issuer.jwk,
                holder_public_key: &issuer.public,
                expected_audience: audience,
                expected_nonce: nonce,
                now_unix: NOW,
                max_iat_age_seconds: 300,
                max_future_iat_skew_seconds: 60,
            }),
        )
        .expect_err("vacuous KB-JWT policy must fail");
        assert!(matches!(error, IetfSdJwtVcError::Verification));
    }
}

#[test]
fn rfc9901_verifier_returns_resolved_payload() {
    let issuer = issuer();
    let (street, street_digest) = encode_disclosure(&json!([SALT, "street", "Main St"]));
    let (address, address_digest) =
        encode_disclosure(&json!([SALT, "address", {"_sd": [street_digest]}]));
    let (country, country_digest) = encode_disclosure(&json!([SALT, "DE"]));
    let artifact = signed_artifact(
        &issuer,
        &json!({
            "iss": "https://issuer.example",
            "_sd": [address_digest],
            "_sd_alg": "sha-256",
            "nationalities": [{"...": country_digest}],
        }),
        vec![street, address, country],
    );
    let verified = verify_rfc9901_sd_jwt(
        &artifact,
        &issuer.jwk,
        &issuer.public,
        &IetfSdJwtTemporalPolicy::new(NOW),
        None,
    )
    .expect("verify");
    assert_eq!(
        verified.resolved_payload,
        json!({
            "iss": "https://issuer.example",
            "address": {"street": "Main St"},
            "nationalities": ["DE"],
        })
    );
    assert_eq!(verified.provided_disclosures.len(), 3);
}

#[test]
fn verifiers_bound_nested_disclosure_recursion() {
    let issuer = issuer();
    let mut disclosures = Vec::new();
    let (leaf, mut digest) = encode_disclosure(&json!([SALT, "leaf", "value"]));
    disclosures.push(leaf);
    for level in 0..64 {
        let (encoded, next) =
            encode_disclosure(&json!([SALT, format!("level{level}"), {"_sd": [digest]}]));
        disclosures.push(encoded);
        digest = next;
    }
    let artifact = signed_artifact(&issuer, &json!({"_sd": [digest]}), disclosures);
    assert!(matches!(
        verify_error(&issuer, &artifact, NOW),
        IetfSdJwtVcError::ProcessingLimitExceeded
    ));
    assert!(matches!(
        legacy_error(&issuer, &artifact, NOW),
        IetfSdJwtVcError::ProcessingLimitExceeded
    ));
}

#[test]
fn verifiers_reject_duplicate_digests_and_kind_mismatches() {
    let issuer = issuer();
    let (name, name_digest) = encode_disclosure(&json!([SALT, "given_name", "Ada"]));
    let duplicated = signed_artifact(
        &issuer,
        &json!({"_sd": [name_digest.clone()], "nested": {"_sd": [name_digest.clone()]}}),
        vec![name.clone()],
    );
    assert!(matches!(
        verify_error(&issuer, &duplicated, NOW),
        IetfSdJwtVcError::InvalidSdClaim
    ));

    let (element, element_digest) = encode_disclosure(&json!([SALT, "DE"]));
    let element_in_object =
        signed_artifact(&issuer, &json!({"_sd": [element_digest]}), vec![element]);
    assert!(matches!(
        verify_error(&issuer, &element_in_object, NOW),
        IetfSdJwtVcError::InvalidDisclosure
    ));

    let property_in_array = signed_artifact(
        &issuer,
        &json!({"list": [{"...": name_digest}]}),
        vec![name],
    );
    assert!(matches!(
        verify_error(&issuer, &property_in_array, NOW),
        IetfSdJwtVcError::InvalidDisclosure
    ));

    let (nested_alg, nested_alg_digest) =
        encode_disclosure(&json!([SALT, "address", {"_sd_alg": "sha-256"}]));
    let misplaced = signed_artifact(
        &issuer,
        &json!({"_sd": [nested_alg_digest]}),
        vec![nested_alg],
    );
    assert!(matches!(
        verify_error(&issuer, &misplaced, NOW),
        IetfSdJwtVcError::ReservedClaimKey
    ));

    let non_string_alg = signed_artifact(&issuer, &json!({"_sd_alg": 256}), Vec::new());
    assert!(matches!(
        verify_error(&issuer, &non_string_alg, NOW),
        IetfSdJwtVcError::InvalidInput
    ));

    let (non_string_salt, non_string_salt_digest) =
        encode_disclosure(&json!([7, "given_name", "Ada"]));
    let bad_salt = signed_artifact(
        &issuer,
        &json!({"_sd": [non_string_salt_digest]}),
        vec![non_string_salt],
    );
    assert!(matches!(
        verify_error(&issuer, &bad_salt, NOW),
        IetfSdJwtVcError::InvalidDisclosure
    ));
}

#[test]
fn verifiers_reject_top_level_disclosure_of_registered_claims() {
    let issuer = issuer();
    for name in ["iss", "nbf", "exp", "cnf", "vct", "vct#integrity", "status"] {
        let (encoded, digest) = encode_disclosure(&json!([SALT, name, "value"]));
        let artifact = signed_artifact(&issuer, &json!({"_sd": [digest]}), vec![encoded]);
        assert!(matches!(
            verify_error(&issuer, &artifact, NOW),
            IetfSdJwtVcError::ReservedClaimKey
        ));
        assert!(matches!(
            legacy_error(&issuer, &artifact, NOW),
            IetfSdJwtVcError::ReservedClaimKey
        ));
    }
}

#[test]
fn ietf_issuance_rejects_claims_colliding_with_registered_fields() {
    let issuer = issuer();
    for (public, selective) in [
        (Some("iss"), None),
        (Some("cnf"), None),
        (Some("me_zk"), None),
        (None, Some("exp")),
        (None, Some("sub")),
        (None, Some("status")),
        (None, Some("vct#integrity")),
        (None, Some("...")),
    ] {
        let mut input = IetfSdJwtIssueInput::new("https://issuer.example");
        let mut public_claims = Map::new();
        if let Some(name) = public {
            public_claims.insert(name.to_owned(), json!("override"));
        }
        let mut selective_claims = Map::new();
        if let Some(name) = selective {
            selective_claims.insert(name.to_owned(), json!("override"));
        }
        input.public_claims = public_claims;
        input.selective_claims = selective_claims;
        assert!(matches!(
            issue_ietf_sd_jwt_vc(&input, &issuer.jwk, &issuer.private),
            Err(IetfSdJwtVcError::ReservedClaimKey)
        ));
    }
}

#[test]
fn rfc9901_issuance_keeps_registered_claims_fixed_and_plaintext() {
    let issuer = issuer();
    for name in ["iss", "sub", "iat", "nbf", "exp", "vct", "cnf"] {
        let input = Rfc9901IssueInput::new("https://issuer.example", json!({name: "override"}));
        assert!(matches!(
            issue_rfc9901_sd_jwt(&input, &issuer.jwk, &issuer.private),
            Err(IetfSdJwtVcError::ReservedClaimKey)
        ));
    }

    let reserved = Rfc9901IssueInput::new("https://issuer.example", json!({"...": "x"}));
    assert!(matches!(
        issue_rfc9901_sd_jwt(&reserved, &issuer.jwk, &issuer.private),
        Err(IetfSdJwtVcError::ReservedClaimKey)
    ));

    let mut paths = Rfc9901IssueInput::new(
        "https://issuer.example",
        json!({"status": {"status_list": {"idx": 1}}}),
    );
    paths.strategy = SelectiveDisclosureStrategy::JsonPaths;
    paths.custom_json_paths = vec!["$.status.status_list".to_owned()];
    assert!(matches!(
        issue_rfc9901_sd_jwt(&paths, &issuer.jwk, &issuer.private),
        Err(IetfSdJwtVcError::ReservedClaimKey)
    ));

    let status = json!({"status_list": {"idx": 1, "uri": "https://issuer.example/status"}});
    let mut all_levels = Rfc9901IssueInput::new(
        "https://issuer.example",
        json!({"status": status.clone(), "given_name": "Ada"}),
    );
    all_levels.strategy = SelectiveDisclosureStrategy::AllLevels;
    let artifact = issue_rfc9901_sd_jwt(&all_levels, &issuer.jwk, &issuer.private).expect("issue");
    let verified = verify_rfc9901_sd_jwt(
        &artifact,
        &issuer.jwk,
        &issuer.public,
        &IetfSdJwtTemporalPolicy::new(NOW),
        None,
    )
    .expect("verify");
    assert_eq!(verified.payload.get("status"), Some(&status));
    assert!(verified.payload.get("given_name").is_none());
    assert_eq!(
        verified.resolved_payload.get("given_name"),
        Some(&json!("Ada"))
    );
}

#[cfg(feature = "conformance-vectors")]
#[test]
fn rfc9901_array_decoys_are_not_pinned_to_the_end() {
    use identity_vc_ietf_sd_jwt::{issue_rfc9901_sd_jwt_deterministic, DecoyPolicy};

    let issuer = issuer();
    let mut positions = std::collections::BTreeSet::new();
    for seed in 1..=32_u64 {
        let mut input =
            Rfc9901IssueInput::new("https://issuer.example", json!({"roles": ["a", "b", "c"]}));
        input.strategy = SelectiveDisclosureStrategy::JsonPaths;
        input.decoys = DecoyPolicy {
            object_decoys: 0,
            array_decoys: 1,
        };
        let artifact =
            issue_rfc9901_sd_jwt_deterministic(&input, &issuer.jwk, &issuer.private, seed)
                .expect("issue");
        let payload_segment = artifact
            .issuer_signed_jwt
            .split('.')
            .nth(1)
            .expect("payload segment");
        let payload: Value = serde_json::from_slice(
            &codec_base64url::base64url_to_bytes(payload_segment).expect("payload b64u"),
        )
        .expect("payload json");
        let roles = payload
            .get("roles")
            .and_then(Value::as_array)
            .expect("roles");
        let position = roles
            .iter()
            .position(|item| item.get("...").is_some())
            .expect("decoy placeholder");
        positions.insert(position);
    }
    assert!(
        positions.len() > 1,
        "decoy placement must vary across salt streams"
    );
}
