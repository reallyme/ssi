// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Security invariants for generated presentation protobuf owners.

#![cfg(feature = "generated")]
#![allow(missing_docs)]

use reallyme_ssi_proto::generated::proto::identity::presentation::v1 as pb;
#[test]
fn sd_jwt_debug_is_redacted() {
    const SD_JWT: &str = "sensitive.header.payload.signature";
    const DISCLOSURE: &str = "sensitive-disclosure";
    const KB_JWT: &str = "sensitive.key.binding.jwt";

    let message = pb::SdJwtVcPresentation {
        sd_jwt: SD_JWT.to_owned(),
        disclosures: vec![DISCLOSURE.to_owned()],
        kb_jwt: Some(KB_JWT.to_owned()),
        vct: Some("credential-type".to_owned()),
        envelope_hash: Some(vec![7_u8; 32]),
        ..Default::default()
    };

    let debug = format!("{message:?}");
    assert!(debug.contains("[REDACTED]"));
    assert!(!debug.contains(SD_JWT));
    assert!(!debug.contains(DISCLOSURE));
    assert!(!debug.contains(KB_JWT));
}

#[test]
fn zk_proof_debug_is_redacted() {
    const PROOF_MARKER: u8 = 0xA7;

    let mut public_inputs: buffa::__private::HashMap<String, Vec<u8>> = Default::default();
    public_inputs.insert("sensitive-input".to_owned(), vec![PROOF_MARKER; 32]);
    let message = pb::ZkProof {
        circuit_id: "sensitive-circuit".to_owned(),
        circuit_version: "sensitive-version".to_owned(),
        vk_id: "sensitive-verification-key".to_owned(),
        proof_bytes: vec![PROOF_MARKER; 64],
        public_inputs,
        artifact_manifest_sha256: vec![PROOF_MARKER; 32],
        ..Default::default()
    };

    let debug = format!("{message:?}");
    assert!(debug.contains("[REDACTED]"));
    assert!(!debug.contains("sensitive-circuit"));
    assert!(!debug.contains("sensitive-input"));
}
