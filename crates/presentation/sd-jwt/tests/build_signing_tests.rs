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
//! Tests for signed SD-JWT VP construction.

use std::collections::BTreeSet;

use identity_presentation_vp_sd_jwt::{
    build_sd_jwt_presentation_with_kb_binding, KbJwtBindingInput,
};

use reallyme_credential::committed::model::{
    ClaimOpening, CredentialAlgorithm, KeyAssurance, KeyReference, MerkleTreeInfo, PublicKeyRef,
    PublicKeyRepresentation, RawPublicKeySerialization, Signature, SubjectPrivateBundle,
};

use crypto_core::Algorithm;
use crypto_dispatch::generate_keypair;
use envelopes_jwk::{Jwk, OkpJwk};

use codec_base64url::{base64url_to_bytes, bytes_to_base64url};

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

#[test]
fn builds_sd_jwt_vp_with_key_binding_jwt() {
    // ------------------------------------------------------------
    // Holder keypair (used ONLY for key-binding JWT)
    // ------------------------------------------------------------
    let (holder_public, holder_private) = generate_keypair(Algorithm::Ed25519).unwrap();

    let holder_jwk = Jwk::Okp(OkpJwk {
        kty: "OKP".into(),
        crv: "Ed25519".into(),
        x: bytes_to_base64url(&holder_public),
        alg: Some("EdDSA".into()),
        kid: Some("holder-key-1".into()),
        use_: None,
    });

    // ------------------------------------------------------------
    // Subject private bundle (issued earlier by issuer)
    // ------------------------------------------------------------
    let bundle = SubjectPrivateBundle {
        holder_key: Some(key("did:test:holder#key-1", holder_public.clone())),
        envelope_hash: vec![9u8; 32],
        issuer_signature: Signature {
            verification_key: key("did:test:issuer#key-1", vec![2; 32]),
            raw_rs: vec![7u8; 64],
        },
        tree: MerkleTreeInfo { depth: 1, count: 1 },
        claims: vec![ClaimOpening {
            claim_path: "/claims/age".into(),
            value: br#"42"#.to_vec(),
            salt: vec![1u8; 16],
            index: 0,
            merkle_path: vec![vec![2u8; 32]],
        }],
    };

    // ------------------------------------------------------------
    // Issuer SD-JWT VC (already signed by issuer)
    // ------------------------------------------------------------
    let issuer_sd_jwt = "issuer.sd.jwt.compact".to_string();

    // ------------------------------------------------------------
    // Build VP with holder key-binding JWT
    // ------------------------------------------------------------
    let vp = build_sd_jwt_presentation_with_kb_binding(
        &bundle,
        issuer_sd_jwt.clone(),
        &["/claims/age".into()],
        &holder_jwk,
        &holder_private,
        KbJwtBindingInput {
            nonce: "request-nonce",
            aud: "verifier.example",
            iat_unix: 1_750_000_000,
        },
    )
    .unwrap();

    // ------------------------------------------------------------
    // Assertions
    // ------------------------------------------------------------

    // Issuer SD-JWT preserved
    assert_eq!(vp.sd_jwt, issuer_sd_jwt);

    // One disclosure
    assert_eq!(vp.disclosures.len(), 1);

    // Envelope hash binding
    assert_eq!(vp.envelope_hash.unwrap(), [9u8; 32]);

    // Key-binding JWT must exist and be a compact JWS
    let kb = vp.kb_jwt.as_deref().expect("kb_jwt must be present");
    let parts: Vec<&str> = kb.split('.').collect();
    assert_eq!(parts.len(), 3, "kb_jwt must be a compact JWS");
    let header: serde_json::Value =
        serde_json::from_slice(&base64url_to_bytes(parts[0]).expect("header decodes"))
            .expect("header is JSON");
    assert_eq!(
        header.get("typ").and_then(serde_json::Value::as_str),
        Some("kb+jwt")
    );
    let payload: serde_json::Value =
        serde_json::from_slice(&base64url_to_bytes(parts[1]).expect("payload decodes"))
            .expect("payload is JSON");
    let claims = payload.as_object().expect("payload is an object");
    assert_eq!(
        claims.keys().map(String::as_str).collect::<BTreeSet<_>>(),
        BTreeSet::from(["aud", "iat", "nonce", "sd_hash"])
    );
}
