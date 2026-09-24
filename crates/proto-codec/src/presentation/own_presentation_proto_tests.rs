// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{
    pb, zeroize_claim_disclosure, zeroize_mdoc_presentation, zeroize_sd_jwt_presentation,
    zeroize_zk_proof,
};

#[test]
fn mdoc_fields_are_cleared() {
    let mut presentation = pb::MdocPresentation {
        device_response: vec![1_u8, 2, 3],
        envelope_hash: Some(vec![4_u8; 32]),
        doc_type: Some("sensitive-document-type".to_owned()),
        ..Default::default()
    };

    zeroize_mdoc_presentation(&mut presentation);

    assert!(presentation.device_response.is_empty());
    assert!(presentation.envelope_hash.is_none());
    assert!(presentation.doc_type.is_none());
}

#[test]
fn sd_jwt_fields_are_cleared() {
    let mut presentation = pb::SdJwtVcPresentation {
        sd_jwt: "sensitive-sd-jwt".to_owned(),
        disclosures: vec!["sensitive-disclosure".to_owned()],
        kb_jwt: Some("sensitive-kb-jwt".to_owned()),
        vct: Some("sensitive-vct".to_owned()),
        envelope_hash: Some(vec![5_u8; 32]),
        ..Default::default()
    };

    zeroize_sd_jwt_presentation(&mut presentation);

    assert!(presentation.sd_jwt.is_empty());
    assert!(presentation.disclosures.is_empty());
    assert!(presentation.kb_jwt.is_none());
    assert!(presentation.vct.is_none());
    assert!(presentation.envelope_hash.is_none());
}

#[test]
fn zk_proof_fields_and_map_entries_are_cleared() {
    let mut public_inputs: buffa::__private::HashMap<String, Vec<u8>> = Default::default();
    public_inputs.insert("sensitive-input".to_owned(), vec![6_u8; 32]);
    let mut proof = pb::ZkProof {
        circuit_id: "sensitive-circuit".to_owned(),
        circuit_version: "sensitive-version".to_owned(),
        vk_id: "sensitive-vk".to_owned(),
        proof_bytes: vec![7_u8; 64],
        public_inputs,
        proof_suite: buffa::EnumValue::from(pb::ZkProofSuite::BarretenbergUltrahonkKeccakZkNoIpa),
        artifact_manifest_sha256: vec![9_u8; 32],
        ..Default::default()
    };

    zeroize_zk_proof(&mut proof);

    assert!(proof.circuit_id.is_empty());
    assert!(proof.circuit_version.is_empty());
    assert!(proof.vk_id.is_empty());
    assert!(proof.proof_bytes.is_empty());
    assert!(proof.public_inputs.is_empty());
    assert_eq!(proof.proof_suite.to_i32(), 0);
    assert!(proof.artifact_manifest_sha256.is_empty());
}

#[test]
fn each_claim_value_variant_is_cleared() {
    let values = [
        pb::__buffa::oneof::claim_disclosure::Value::RevealedValue(vec![8_u8; 16]),
        pb::__buffa::oneof::claim_disclosure::Value::Threshold(18),
        pb::__buffa::oneof::claim_disclosure::Value::Range(Box::new(pb::Range {
            min: 10,
            max: 20,
            ..Default::default()
        })),
        pb::__buffa::oneof::claim_disclosure::Value::Set(Box::new(pb::ValueSet {
            values: vec![vec![9_u8; 16]],
            ..Default::default()
        })),
    ];

    for value in values {
        let mut disclosure = pb::ClaimDisclosure {
            claim_path: "/sensitive".to_owned(),
            value: Some(value),
            ..Default::default()
        };

        zeroize_claim_disclosure(&mut disclosure);

        assert!(disclosure.claim_path.is_empty());
        assert!(disclosure.value.is_none());
    }
}
