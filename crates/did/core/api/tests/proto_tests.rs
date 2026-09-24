// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Test coverage for this crate.
#![allow(missing_docs)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::panic)]
#![allow(clippy::expect_used)]

use reallyme_did_api::{
    create::create_did,
    proto::{did_to_proto_brotli, proto_brotli_to_did},
    CreateConfig, DidProfile,
};

#[test]
fn proto_roundtrip_preserves_did_document() {
    let did = "did:me:proto-api";

    // --------------------------------------------------
    // 1. Create a DID via the API
    // --------------------------------------------------
    let cfg = CreateConfig {
        profile: Some(DidProfile::CoreIdentity),
        also_known_as: None,
        hardware_bound: None,
        biometric_protected: None,
        user_verification_method: None,
        device_model: None,
        services: None,
        update_policy: None,
        domain_verification: None,

        verification_methods: None,
        authentication: None,
        assertion: None,
        invocation: None,
        key_agreement: None,
        created: Some("2025-01-01T00:00:00Z".into()),
    };

    let (doc, _ks) = create_did(cfg, did).expect("create_did failed");

    // Sanity: core fields
    assert!(doc.id.starts_with("did:me:me1"));
    assert_ne!(doc.id, did);
    assert!(!doc.current_core.is_empty());
    assert!(!doc.core_cbor.is_empty());

    // --------------------------------------------------
    // 2. JSON → Proto (brotli)
    // --------------------------------------------------
    let proto_bytes = did_to_proto_brotli(&doc).expect("json → proto failed");

    assert!(!proto_bytes.is_empty(), "proto bytes must not be empty");

    // --------------------------------------------------
    // 3. Proto → JSON
    // --------------------------------------------------
    let roundtrip_doc = proto_brotli_to_did(&proto_bytes).expect("proto → json failed");

    // --------------------------------------------------
    // 4. Core invariants preserved
    // --------------------------------------------------
    assert_eq!(roundtrip_doc.id, doc.id);
    assert_eq!(roundtrip_doc.current_core, doc.current_core);
    assert_eq!(roundtrip_doc.sequence, doc.sequence);

    // Verification methods preserved
    assert_eq!(
        roundtrip_doc.verification_method.len(),
        doc.verification_method.len()
    );

    // Update policy preserved
    let pol = roundtrip_doc
        .update_policy
        .as_ref()
        .expect("missing updatePolicy");
    assert!(!pol.allowed_verification_methods.is_empty());
    assert_eq!(pol.threshold, Some(2));

    // --------------------------------------------------
    // 5. DataIntegrityProof preserved (if present)
    // --------------------------------------------------
    if let Some(proof) = &doc.data_integrity_proof {
        let rt_proof = roundtrip_doc
            .data_integrity_proof
            .as_ref()
            .expect("missing proof after roundtrip");

        assert_eq!(rt_proof.proof_type, proof.proof_type);
        assert_eq!(rt_proof.cryptosuite, proof.cryptosuite);
        assert_eq!(rt_proof.verification_method, proof.verification_method);
        assert_eq!(rt_proof.jws, proof.jws);
    }
}
