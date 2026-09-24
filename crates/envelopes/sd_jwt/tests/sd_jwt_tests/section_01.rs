// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use reallyme_sd_jwt::{
    build_key_binding_jwt, create_array_element_disclosure, create_object_property_disclosure,
    decode_disclosure, digest_disclosure, issue_sd_jwt, parse_sd_jwt_compact,
    parse_sd_jwt_json_serialization, parse_sd_jwt_or_kb_compact, process_sd_jwt_payload,
    serialize_sd_jwt_compact, verify_sd_jwt, verify_sd_jwt_receipt,
    verify_sd_jwt_receipt_with_x5c, DecoyPolicy, DisclosureKind, KeyBindingJwtBuildOptions,
    KeyBindingVerificationOptions, SdJwtDisclosureStrategy, SdJwtEnvelopeError, SdJwtHashAlgorithm,
    SdJwtIssuanceInput, SdJwtIssuancePolicy, SdJwtOrKbCompact, SdJwtProcessingPolicy,
    SdJwtReceiptVerificationPolicy, SdJwtSaltSource, SdJwtVerificationOptions,
    MAX_SD_JWT_COMPACT_BYTES, MAX_SD_JWT_DISCLOSURES, MAX_SD_JWT_DISCLOSURE_BYTES,
    MAX_SD_JWT_JSON_SIGNATURES,
};
use reallyme_codec::base64url::{base64url_to_bytes, bytes_to_base64url};
use reallyme_crypto::core::{Algorithm, HashAlgorithm};
use reallyme_crypto::dispatch::{generate_keypair, hash_digest, sign};
use reallyme_crypto::jwk::{
    ed25519_public_key_to_jwk, p256_public_key_to_jwk, Jwk, JwkOptions,
};
use reallyme_crypto::p256::{decompress_public_key, p256_ecdsa_der_to_jose_signature};
use reallyme_jose::jwt::{encode_signed_jwt_with_header_options, JwtHeaderEncodeOptions};
use serde_json::Map;
use serde_json::{json, Value};
use zeroize::{Zeroize, ZeroizeOnDrop};

const IETF_SD_JWT_VECTORS_ENV: &str = "REALLYME_IETF_SD_JWT_VECTORS_DIR";
const RFC9901_VECTORS_ENV: &str = "REALLYME_SD_JWT_RFC9901_VECTORS_DIR";

fn strip_ascii_whitespace(input: &str) -> String {
    input.chars().filter(|c| !c.is_ascii_whitespace()).collect()
}

fn load_string(path: &Path) -> String {
    let content = fs::read_to_string(path).unwrap_or_else(|err| {
        panic!("failed to read {}: {err}", path.display());
    });
    strip_ascii_whitespace(&content)
}

fn load_json(path: &Path) -> Value {
    let content = fs::read_to_string(path).unwrap_or_else(|err| {
        panic!("failed to read {}: {err}", path.display());
    });
    serde_json::from_str(&content).unwrap_or_else(|err| {
        panic!("failed to parse {}: {err}", path.display());
    })
}

fn sanitize_json_for_parsing(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut in_string = false;
    let mut escaped = false;

    for character in input.chars() {
        if in_string {
            if escaped {
                out.push(character);
                escaped = false;
                continue;
            }
            if character == '\\' {
                out.push(character);
                escaped = true;
                continue;
            }
            if character == '"' {
                out.push(character);
                in_string = false;
                continue;
            }
            if character == '\n' || character == '\r' || character == '\t' {
                out.push(' ');
                continue;
            }
            out.push(character);
        } else {
            out.push(character);
            if character == '"' {
                in_string = true;
            }
        }
    }

    out
}

fn workspace_root() -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .parent()
        .and_then(Path::parent)
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .expect("crate must live under crates/envelopes/sd_jwt")
}

fn ietf_vectors_root() -> PathBuf {
    std::env::var_os(IETF_SD_JWT_VECTORS_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|| workspace_root().join("vectors").join("ietf-sd-jwt"))
}

fn rfc9901_vectors_root() -> PathBuf {
    std::env::var_os(RFC9901_VECTORS_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|| workspace_root().join("vectors").join("sd-jwt-rfc9901"))
}

fn vector_case(name: &str) -> PathBuf {
    ietf_vectors_root().join(name)
}

fn local_vectors_available() -> bool {
    ietf_vectors_root().exists()
}

fn decode_jwt_payload(jwt: &str) -> Value {
    let mut parts = jwt.split('.');
    let _header = parts.next().expect("JWT header segment");
    let payload = parts.next().expect("JWT payload segment");
    let _signature = parts.next().expect("JWT signature segment");
    assert!(
        parts.next().is_none(),
        "JWT must have exactly three segments"
    );

    let payload_bytes = base64url_to_bytes(payload).expect("JWT payload must be base64url");
    serde_json::from_slice(&payload_bytes).expect("JWT payload must be JSON")
}

fn expected_full_user_payload(vector: &Value) -> Value {
    let expected_payload = vector
        .get("expected_payload")
        .and_then(Value::as_object)
        .expect("vector expected_payload object");
    let user_claims = vector
        .get("user_claims")
        .and_then(Value::as_object)
        .expect("vector user_claims object");

    let mut merged = Map::new();
    for (key, value) in expected_payload {
        if key != "_sd" && key != "_sd_alg" {
            merged.insert(key.clone(), value.clone());
        }
    }
    for (key, value) in user_claims {
        merged.insert(key.clone(), value.clone());
    }

    Value::Object(merged)
}

fn expected_undisclosed_payload(payload: &Value) -> Value {
    let mut object = payload
        .as_object()
        .expect("payload fixture must be an object")
        .clone();
    object.remove("_sd");
    object.remove("_sd_alg");
    Value::Object(object)
}

struct TestKey {
    public: Vec<u8>,
    private: Vec<u8>,
    jwk: Jwk,
}

fn gen_ed25519() -> TestKey {
    let (public, private) = generate_keypair(Algorithm::Ed25519).expect("generate Ed25519 keypair");
    let jwk = ed25519_public_key_to_jwk(
        &public,
        JwkOptions {
            alg: true,
            use_sig: true,
            use_enc: false,
            kid: Some("test-key".to_owned()),
        },
    )
    .expect("convert Ed25519 key to JWK");

    TestKey {
        public,
        private: private.to_vec(),
        jwk: Jwk::Okp(jwk.into()),
    }
}

fn gen_p256() -> TestKey {
    let (public, private) = generate_keypair(Algorithm::P256).expect("generate P-256 keypair");
    let jwk = p256_public_key_to_jwk(
        &public,
        JwkOptions {
            alg: true,
            use_sig: true,
            use_enc: false,
            kid: Some("test-p256-key".to_owned()),
        },
    )
    .expect("convert P-256 key to JWK");
    TestKey {
        public,
        private: private.to_vec(),
        jwk: Jwk::Ec(jwk),
    }
}

struct DeterministicSaltSource {
    next: u32,
}

impl DeterministicSaltSource {
    fn new() -> Self {
        DeterministicSaltSource { next: 0 }
    }

    fn next_id(&mut self) -> u32 {
        self.next = self
            .next
            .checked_add(1)
            .expect("test counter must not overflow");
        self.next
    }
}

impl SdJwtSaltSource for DeterministicSaltSource {
    fn next_salt(&mut self) -> Result<String, SdJwtEnvelopeError> {
        let mut salt = [0xA5_u8; 16];
        salt[12..].copy_from_slice(&self.next_id().to_be_bytes());
        Ok(bytes_to_base64url(&salt))
    }

    fn next_decoy_digest(&mut self) -> Result<String, SdJwtEnvelopeError> {
        let mut digest = [0x5A_u8; 32];
        digest[28..].copy_from_slice(&self.next_id().to_be_bytes());
        Ok(bytes_to_base64url(&digest))
    }
}

fn contains_decoy_digest(value: &Value) -> bool {
    fn is_test_decoy(digest: &str) -> bool {
        base64url_to_bytes(digest).is_ok_and(|decoded| {
            decoded.len() == 32 && decoded[..28].iter().all(|byte| *byte == 0x5A)
        })
    }

    match value {
        Value::Object(object) => {
            let object_decoy = object
                .get("_sd")
                .and_then(Value::as_array)
                .is_some_and(|digests| {
                    digests
                        .iter()
                        .any(|digest| digest.as_str().is_some_and(is_test_decoy))
                });
            let array_decoy = object
                .get("...")
                .and_then(Value::as_str)
                .is_some_and(is_test_decoy);

            object_decoy || array_decoy || object.values().any(contains_decoy_digest)
        }
        Value::Array(array) => array.iter().any(contains_decoy_digest),
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => false,
    }
}

#[test]
fn object_property_disclosure_round_trips_and_matches_digest_vector() {
    let encoded = "WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwgInRlc3RfbnVsbCIsIG51bGxd";
    let disclosure = decode_disclosure(encoded).expect("fixture disclosure must decode");

    assert_eq!(disclosure.salt(), "2GLC42sKQveCfGfryNRN9w");
    assert_eq!(
        disclosure.kind(),
        &DisclosureKind::ObjectProperty {
            claim_name: "test_null".to_owned(),
            claim_value: Value::Null,
        }
    );
    assert_eq!(
        digest_disclosure(encoded, SdJwtHashAlgorithm::Sha256)
            .expect("fixture disclosure digest must compute"),
        "8-VkGP36dOmWLNRqsN7GbaHR7SrjT3TZBhCHNQmM2oY"
    );
}

#[test]
fn disclosure_creation_uses_canonical_json_and_hashes_encoded_form() {
    let disclosure = create_object_property_disclosure(
        "MDEyMzQ1Njc4OWFiY2RlZg",
        "name",
        json!({"a": 1}),
    )
        .expect("valid object disclosure must encode");
    let decoded_json = base64url_to_bytes(disclosure.encoded()).expect("encoded disclosure");
    assert_eq!(
        decoded_json,
        br#"["MDEyMzQ1Njc4OWFiY2RlZg","name",{"a":1}]"#
    );

    let digest = digest_disclosure(disclosure.encoded(), SdJwtHashAlgorithm::Sha256)
        .expect("disclosure digest must compute");
    let digest_again = digest_disclosure(disclosure.encoded(), SdJwtHashAlgorithm::Sha256)
        .expect("disclosure digest must be deterministic");
    assert_eq!(digest, digest_again);
}

#[test]
fn array_element_disclosure_round_trips() {
    let disclosure =
        create_array_element_disclosure("MDEyMzQ1Njc4OWFiY2RlZg", json!(["nested", true]))
            .expect("valid disclosure");
    let decoded = decode_disclosure(disclosure.encoded()).expect("created disclosure must decode");

    assert_eq!(
        decoded.kind(),
        &DisclosureKind::ArrayElement {
            claim_value: json!(["nested", true]),
        }
    );
}

#[test]
fn compact_sd_jwt_serialization_round_trips() {
    let issuer_jwt = "a.b.c";
    let disclosures = vec!["d1".to_owned(), "d2".to_owned()];
    let compact = serialize_sd_jwt_compact(issuer_jwt, &disclosures)
        .expect("valid SD-JWT compact must serialize");

    assert_eq!(compact, "a.b.c~d1~d2~");
    let parsed = parse_sd_jwt_compact(&compact).expect("serialized compact must parse");
    assert_eq!(parsed.issuer_signed_jwt, issuer_jwt);
    assert_eq!(parsed.disclosures, disclosures);
}

#[test]
fn compact_sd_jwt_with_key_binding_parses_final_jwt() {
    match parse_sd_jwt_or_kb_compact("a.b.c~d1~h.i.j").expect("valid SD-JWT+KB must parse") {
        SdJwtOrKbCompact::SdJwtWithKb(parsed) => {
            assert_eq!(parsed.issuer_signed_jwt, "a.b.c");
            assert_eq!(parsed.disclosures, vec!["d1".to_owned()]);
            assert_eq!(parsed.key_binding_jwt, "h.i.j");
        }
        SdJwtOrKbCompact::SdJwt(_) => panic!("expected key binding compact form"),
    }
}

#[test]
fn compact_sd_jwt_rejects_too_many_disclosures() {
    let mut compact = String::from("a.b.c");
    for _ in 0..=MAX_SD_JWT_DISCLOSURES {
        compact.push_str("~disclosure");
    }
    compact.push('~');

    let err =
        parse_sd_jwt_compact(&compact).expect_err("oversized disclosure count must be rejected");

    assert!(matches!(err, SdJwtEnvelopeError::TooManyDisclosures));
}

#[test]
fn compact_sd_jwt_rejects_oversized_disclosure() {
    let disclosure = "a".repeat(MAX_SD_JWT_DISCLOSURE_BYTES + 1);
    let compact = format!("a.b.c~{disclosure}~");

    let err = parse_sd_jwt_compact(&compact).expect_err("oversized disclosure must be rejected");

    assert!(matches!(err, SdJwtEnvelopeError::DisclosureTooLarge));
}

#[test]
fn compact_sd_jwt_rejects_oversized_total_input_before_parsing() {
    let compact = format!("a.b.{}~", "c".repeat(MAX_SD_JWT_COMPACT_BYTES));

    let error = parse_sd_jwt_compact(&compact)
        .expect_err("oversized compact input must be rejected before component parsing");

    assert!(matches!(error, SdJwtEnvelopeError::InputTooLarge));
}

#[test]
fn compact_owner_redacts_and_zeroizes_tokens_and_disclosures() {
    fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}
    assert_zeroize_on_drop::<reallyme_sd_jwt::SdJwtCompact>();

    let mut parsed = parse_sd_jwt_compact("issuer.payload.signature~private-disclosure~")
        .expect("bounded compact input must parse");
    let diagnostics = format!("{parsed:?}");
    assert!(!diagnostics.contains("issuer.payload.signature"));
    assert!(!diagnostics.contains("private-disclosure"));

    parsed.zeroize();
    assert!(parsed.issuer_signed_jwt.is_empty());
    assert!(parsed.disclosures.is_empty());
}

#[test]
fn json_serialization_rejects_excessive_signature_fanout() {
    let signatures = (0..=MAX_SD_JWT_JSON_SIGNATURES)
        .map(|_| json!({"protected": "a", "signature": "c"}))
        .collect::<Vec<Value>>();
    let input = json!({"payload": "b", "signatures": signatures}).to_string();

    let error = parse_sd_jwt_json_serialization(&input)
        .expect_err("excessive signature fanout must fail closed");

    assert!(matches!(error, SdJwtEnvelopeError::TooManySignatures));
}

#[test]
fn process_sd_jwt_payload_resolves_recursive_owf_vector() {
    if !local_vectors_available() {
        return;
    }

    let case_dir = vector_case("array_recursive_sd_some_disclosed");
    let payload = load_json(&case_dir.join("sd_jwt_payload.json"));
    let expected = load_json(&case_dir.join("verified_contents.json"));
    let compact = load_string(&case_dir.join("sd_jwt_presentation.txt"));
    let parsed = parse_sd_jwt_compact(&compact).expect("presentation compact must parse");

    let resolved = process_sd_jwt_payload(
        payload,
        &parsed.disclosures,
        SdJwtProcessingPolicy::default(),
    )
    .expect("OWF recursive presentation must resolve");

    assert_eq!(resolved, expected);
}

#[test]
fn process_sd_jwt_payload_resolves_each_local_owf_presentation_vector() {
    let root = ietf_vectors_root();
    if !root.exists() {
        return;
    }

    let entries = fs::read_dir(&root).unwrap_or_else(|err| {
        panic!("failed to read {}: {err}", root.display());
    });

    let mut processed = 0usize;
    for entry in entries {
        let entry = entry.unwrap_or_else(|err| panic!("failed to read vector dir entry: {err}"));
        let case_dir = entry.path();
        if !case_dir.is_dir() {
            continue;
        }

        let presentation = case_dir.join("sd_jwt_presentation.txt");
        let payload_path = case_dir.join("sd_jwt_payload.json");
        let verified_path = case_dir.join("verified_contents.json");
        if !presentation.exists() || !payload_path.exists() || !verified_path.exists() {
            continue;
        }

        let payload = load_json(&payload_path);
        let expected = load_json(&verified_path);
        let compact = load_string(&presentation);
        let disclosures = match parse_sd_jwt_or_kb_compact(&compact).unwrap_or_else(|err| {
            panic!("{}: compact parse failed: {err}", case_dir.display());
        }) {
            SdJwtOrKbCompact::SdJwt(parsed) => parsed.disclosures.clone(),
            SdJwtOrKbCompact::SdJwtWithKb(parsed) => parsed.disclosures.clone(),
        };
        let resolved =
            process_sd_jwt_payload(payload, &disclosures, SdJwtProcessingPolicy::default())
                .unwrap_or_else(|err| {
                    panic!(
                        "{}: SD-JWT payload processing failed: {err}",
                        case_dir.display()
                    );
                });

        assert_eq!(resolved, expected, "{} mismatch", case_dir.display());
        processed = processed
            .checked_add(1)
            .expect("small vector suite count must not overflow");
    }

    assert!(processed > 0, "expected local OWF SD-JWT vectors");
}

#[test]
fn rfc9901_vectors_decode_payloads_and_resolve_full_issuance() {
    let root = rfc9901_vectors_root();
    let manifest = load_json(&root.join("manifest.json"));
    let vectors = manifest
        .get("vectors")
        .and_then(Value::as_array)
        .expect("manifest vectors array");

    for vector_name in vectors {
        let vector_name = vector_name.as_str().expect("manifest vector name");
        let vector_path = root.join(vector_name);
        let vector = load_json(&vector_path);
        let issued_compact = vector
            .get("issued_compact")
            .and_then(Value::as_str)
            .expect("issued compact string");
        let parsed = parse_sd_jwt_compact(issued_compact).unwrap_or_else(|err| {
            panic!(
                "{}: issued compact parse failed: {err}",
                vector_path.display()
            );
        });

        let decoded_payload = decode_jwt_payload(&parsed.issuer_signed_jwt);
        assert_eq!(
            decoded_payload,
            vector
                .get("expected_payload")
                .expect("expected payload fixture")
                .clone(),
            "{} issuer payload mismatch",
            vector_path.display()
        );

        let resolved = process_sd_jwt_payload(
            decoded_payload,
            &parsed.disclosures,
            SdJwtProcessingPolicy::default(),
        )
        .unwrap_or_else(|err| {
            panic!(
                "{}: full issuance disclosure processing failed: {err}",
                vector_path.display()
            );
        });

        assert_eq!(
            resolved,
            expected_full_user_payload(&vector),
            "{} resolved issuance payload mismatch",
            vector_path.display()
        );
    }
}

#[test]
fn jws_json_serialization_vectors_parse_and_process() {
    for case_name in ["json_serialization_flattened", "json_serialization_general"] {
        let case_dir = vector_case(case_name);
        let presentation_json = fs::read_to_string(case_dir.join("sd_jwt_presentation.json"))
            .unwrap_or_else(|err| panic!("{case_name}: read presentation JSON: {err}"));
        let sanitized_json = sanitize_json_for_parsing(&presentation_json);
        let parsed = parse_sd_jwt_json_serialization(&sanitized_json)
            .unwrap_or_else(|err| panic!("{case_name}: parse JSON serialization: {err}"));
        assert!(
            !parsed.entries.is_empty(),
            "{case_name}: expected signatures"
        );

        let expected_payload = load_json(&case_dir.join("sd_jwt_payload.json"));
        let expected_verified = load_json(&case_dir.join("verified_contents.json"));
        let mut entries_with_disclosures = 0usize;
        for entry in &parsed.entries {
            let compact = entry.to_compact().expect("JSON entry compact form");
            parse_sd_jwt_or_kb_compact(&compact).expect("JSON entry must become compact SD-JWT");
            let payload = decode_jwt_payload(entry.issuer_signed_jwt());
            assert_eq!(payload, expected_payload, "{case_name}: issuer payload");

            let expected_resolved = if entry.disclosures().is_empty() {
                expected_undisclosed_payload(&expected_payload)
            } else {
                entries_with_disclosures = entries_with_disclosures
                    .checked_add(1)
                    .expect("small vector count");
                expected_verified.clone()
            };
            let resolved = process_sd_jwt_payload(
                payload,
                entry.disclosures(),
                SdJwtProcessingPolicy::default(),
            )
            .unwrap_or_else(|err| panic!("{case_name}: process JSON serialization: {err}"));
            assert_eq!(resolved, expected_resolved, "{case_name}: resolved payload");
        }
        assert!(
            entries_with_disclosures > 0,
            "{case_name}: expected one signature entry with disclosures"
        );
    }
}

#[test]
fn issue_sd_jwt_top_level_roundtrip_verifies() {
    let issuer = gen_ed25519();
    let claims = json!({
        "iss": "https://example.com/issuer",
        "given_name": "Max",
        "family_name": "Mustermann",
        "address": {
            "street_address": "Schulstr. 12",
            "locality": "Schulpforta",
        },
    });
    let mut salts = DeterministicSaltSource::new();

    let issued = issue_sd_jwt(
        SdJwtIssuanceInput {
            claims: claims.clone(),
            issuer_jwk: &issuer.jwk,
            issuer_private_key: &issuer.private,
            policy: SdJwtIssuancePolicy::default(),
        },
        &mut salts,
    )
    .expect("valid SD-JWT issuance must succeed");

    assert_eq!(issued.records.len(), 4);
    assert!(issued.issuer_payload.get("_sd").is_some());
    assert_eq!(
        issued.issuer_payload.get("_sd_alg").and_then(Value::as_str),
        Some("sha-256")
    );
    assert!(issued.issuer_payload.get("given_name").is_none());

    let verified = verify_sd_jwt(
        &issued.compact,
        &issuer.jwk,
        &issuer.public,
        &SdJwtVerificationOptions::default(),
    )
    .expect("issued SD-JWT must verify");

    assert_eq!(verified.issuer_payload, issued.issuer_payload);
    assert_eq!(verified.resolved_payload, claims);
}

#[test]
fn issue_sd_jwt_all_levels_supports_array_elements_and_decoys() {
    let issuer = gen_ed25519();
    let claims = json!({
        "iss": "https://example.com/issuer",
        "given_name": "Max",
        "roles": ["driver", "resident"],
        "address": {
            "street_address": "Schulstr. 12",
            "locality": "Schulpforta",
        },
    });
    let policy = SdJwtIssuancePolicy {
        disclosure_strategy: SdJwtDisclosureStrategy::AllLevels,
        decoys: DecoyPolicy {
            object_decoys: 1,
            array_decoys: 1,
        },
        ..SdJwtIssuancePolicy::default()
    };
    let mut salts = DeterministicSaltSource::new();

    let issued = issue_sd_jwt(
        SdJwtIssuanceInput {
            claims: claims.clone(),
            issuer_jwk: &issuer.jwk,
            issuer_private_key: &issuer.private,
            policy,
        },
        &mut salts,
    )
    .expect("valid nested SD-JWT issuance must succeed");

    assert!(issued.records.len() >= 7);
    assert!(contains_decoy_digest(&issued.issuer_payload));

    let verified = verify_sd_jwt(
        &issued.compact,
        &issuer.jwk,
        &issuer.public,
        &SdJwtVerificationOptions::default(),
    )
    .expect("nested issued SD-JWT must verify");

    assert_eq!(verified.resolved_payload, claims);
}

#[test]
fn issue_sd_jwt_rejects_reserved_claim_names() {
    let issuer = gen_ed25519();
    let mut salts = DeterministicSaltSource::new();
    let err = issue_sd_jwt(
        SdJwtIssuanceInput {
            claims: json!({
                "iss": "https://example.com/issuer",
                "_sd": [],
            }),
            issuer_jwk: &issuer.jwk,
            issuer_private_key: &issuer.private,
            policy: SdJwtIssuancePolicy::default(),
        },
        &mut salts,
    )
    .expect_err("reserved SD-JWT claims must fail issuance");

    assert!(matches!(
        err,
        SdJwtEnvelopeError::InvalidReservedClaimPlacement
    ));
}

#[test]
fn verify_sd_jwt_verifies_issuer_signature_and_resolves_payload() {
    let issuer = gen_ed25519();
    let disclosure =
        create_object_property_disclosure(
            "MDEyMzQ1Njc4OWFiY2RlZg",
            "given_name",
            json!("Max"),
        )
        .expect("disclosure");
    let digest =
        digest_disclosure(disclosure.encoded(), SdJwtHashAlgorithm::Sha256).expect("digest");
    let issuer_payload = json!({
        "iss": "https://example.com/issuer",
        "iat": 1683000000u64,
        "_sd": [digest],
        "_sd_alg": "sha-256",
    });
    let issuer_signed_jwt = encode_signed_jwt_with_header_options(
        &issuer_payload,
        &issuer.jwk,
        &issuer.private,
        &JwtHeaderEncodeOptions::new(Some("dc+sd-jwt".to_owned())),
    )
    .expect("issuer JWT");
    let compact = serialize_sd_jwt_compact(&issuer_signed_jwt, &[disclosure.encoded().to_owned()])
        .expect("compact");

    let verified = verify_sd_jwt(
        &compact,
        &issuer.jwk,
        &issuer.public,
        &SdJwtVerificationOptions::default(),
    )
    .expect("verified SD-JWT");

    assert_eq!(verified.issuer_payload, issuer_payload);
    assert_eq!(
        verified.resolved_payload,
        json!({
            "iss": "https://example.com/issuer",
            "iat": 1683000000u64,
            "given_name": "Max",
        })
    );
}
