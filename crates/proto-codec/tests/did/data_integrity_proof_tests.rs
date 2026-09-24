// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Test coverage for this crate.
#![allow(missing_docs)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::panic)]
#![allow(clippy::expect_used)]

use reallyme_did_types::DataIntegrityProof as JsonProof;
use reallyme_ssi_proto::generated::proto::meid::did::v1::DataIntegrityProof as PbProof;
use reallyme_ssi_proto_codec::did::mapping::data_integrity_proof::{
    di_proof_from_proto, di_proof_to_proto,
};

#[test]
fn json_to_proto_roundtrip_preserves_fields() {
    let j = JsonProof {
        proof_type: "DataIntegrityProof".to_string(),
        cryptosuite: Some("es256-jws-cid-2025".to_string()),
        verification_method: Some("did:example:123#p256".to_string()),
        created: Some("2025-01-01T00:00:00Z".to_string()),
        jws: Some("header.payload.sig".to_string()),
        proof_purpose: Some("assertionMethod".to_string()),
    };

    let p: PbProof = di_proof_to_proto(&j);

    assert_eq!(p.r#type, "DataIntegrityProof");
    assert_eq!(p.cryptosuite, "es256-jws-cid-2025");
    assert_eq!(p.verification_method, "did:example:123#p256");
    assert_eq!(p.created, "2025-01-01T00:00:00Z");
    assert_eq!(p.jws, "header.payload.sig");
    assert_eq!(p.proof_purpose, "assertionMethod");
}

#[test]
fn proto_to_json_roundtrip_preserves_fields() {
    let p = PbProof {
        r#type: "DataIntegrityProof".to_string(),
        cryptosuite: "es256-jws-cid-2025".to_string(),
        verification_method: "did:example:123#p256".to_string(),
        created: "2025-01-01T00:00:00Z".to_string(),
        jws: "header.payload.sig".to_string(),
        proof_purpose: "assertionMethod".to_string(),
        ..PbProof::default()
    };

    let j = di_proof_from_proto(&p);

    assert_eq!(j.proof_type, "DataIntegrityProof");
    assert_eq!(j.cryptosuite.as_deref(), Some("es256-jws-cid-2025"));
    assert_eq!(
        j.verification_method.as_deref(),
        Some("did:example:123#p256")
    );
    assert_eq!(j.created.as_deref(), Some("2025-01-01T00:00:00Z"));
    assert_eq!(j.jws.as_deref(), Some("header.payload.sig"));
    assert_eq!(j.proof_purpose.as_deref(), Some("assertionMethod"));
}

#[test]
fn proto_to_json_converts_empty_strings_to_none() {
    let p = PbProof {
        r#type: "DataIntegrityProof".to_string(),
        cryptosuite: "".to_string(),
        verification_method: "".to_string(),
        created: "".to_string(),
        jws: "".to_string(),
        proof_purpose: "".to_string(),
        ..PbProof::default()
    };

    let j = di_proof_from_proto(&p);

    assert_eq!(j.proof_type, "DataIntegrityProof");
    assert!(j.cryptosuite.is_none());
    assert!(j.verification_method.is_none());
    assert!(j.created.is_none());
    assert!(j.jws.is_none());
    assert!(j.proof_purpose.is_none());
}

#[test]
fn json_to_proto_converts_none_to_empty_strings() {
    let j = JsonProof {
        proof_type: "DataIntegrityProof".to_string(),
        cryptosuite: None,
        verification_method: None,
        created: None,
        jws: None,
        proof_purpose: None,
    };

    let p = di_proof_to_proto(&j);

    assert_eq!(p.r#type, "DataIntegrityProof");
    assert_eq!(p.cryptosuite, "");
    assert_eq!(p.verification_method, "");
    assert_eq!(p.created, "");
    assert_eq!(p.jws, "");
    assert_eq!(p.proof_purpose, "");
}
