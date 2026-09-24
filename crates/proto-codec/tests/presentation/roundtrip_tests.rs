// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! VP protobuf codec tests.

#![allow(missing_docs)]
#![allow(clippy::panic)]

use std::collections::BTreeMap;

use reallyme_ssi_proto_codec::presentation::{
    decode_presentation_proto, decode_presentation_proto_brotli, decode_proto,
    encode_presentation_proto, encode_presentation_proto_brotli, encode_proto, json_to_proto,
    presentation_to_proto_json, proto_json_to_presentation, proto_to_presentation, VpProtoError,
    MAX_MDOC_DEVICE_RESPONSE_BYTES, MAX_PRESENTATION_PROTO_JSON_BYTES,
    MAX_PRESENTATION_PROTO_MESSAGE_BYTES,
};
use reallyme_vp_core::{
    ClaimDisclosure, CredentialReference, CredentialStatusRef, DisclosureMode, MdocPresentation,
    Presentation, PresentationFreshness, QeaaVerifierHints, Range, SdJwtVcPresentation,
    StatusPurpose, ValueSet, ZkPresentation, ZkProof,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}

fn sd_jwt_presentation() -> Presentation {
    Presentation::SdJwtVc(Box::new(SdJwtVcPresentation {
        sd_jwt: "header.payload.signature".to_owned(),
        disclosures: vec!["disclosure-1".to_owned(), "disclosure-2".to_owned()],
        kb_jwt: Some("kb.header.payload.signature".to_owned()),
        vct: Some("eu.pid.v1".to_owned()),
        envelope_hash: Some([7u8; 32]),
    }))
}

fn zk_presentation() -> Presentation {
    let mut public_inputs = BTreeMap::new();
    public_inputs.insert("age_over_18".to_owned(), vec![1]);

    Presentation::Zk(Box::new(ZkPresentation {
        freshness: PresentationFreshness {
            challenge: [1u8; 32],
            audience_hash: [2u8; 32],
            expiry_unix: 1_700_000_000,
        },
        credential: CredentialReference {
            envelope_hash: [3u8; 32],
            issuer_did: "did:me:test".to_owned(),
            status: CredentialStatusRef {
                status_list_url: "https://issuer.example/status/1".to_owned(),
                status_list_id: [4u8; 32],
                status_list_index: 42,
                purpose: StatusPurpose::Revocation,
            },
        },
        disclosures: vec![
            ClaimDisclosure {
                claim_path: "/age".to_owned(),
                mode: DisclosureMode::Gte,
                revealed_value: None,
                threshold: Some(18),
                range: None,
                set: None,
            },
            ClaimDisclosure {
                claim_path: "/country".to_owned(),
                mode: DisclosureMode::MemberOfSet,
                revealed_value: None,
                threshold: None,
                range: None,
                set: Some(ValueSet {
                    values: vec![b"MT".to_vec(), b"DE".to_vec()],
                }),
            },
            ClaimDisclosure {
                claim_path: "/income".to_owned(),
                mode: DisclosureMode::Range,
                revealed_value: None,
                threshold: None,
                range: Some(Range { min: 100, max: 200 }),
                set: None,
            },
        ],
        zk_proof: ZkProof {
            circuit_id: "pid-age".to_owned(),
            circuit_version: "1".to_owned(),
            vk_id: "vk-1".to_owned(),
            proof_bytes: vec![9, 8, 7],
            public_inputs,
            proof_suite: reallyme_vp_core::ZkProofSuite::BarretenbergUltraHonkKeccakZkNoIpa,
            artifact_manifest_sha256: [9_u8; 32],
        },
        qeaa: Some(QeaaVerifierHints {
            required: true,
            audit_report_hash: Some([8u8; 32]),
            max_status_age_seconds: 3_600,
        }),
    }))
}

#[test]
fn sd_jwt_presentation_round_trips_through_proto_bytes() -> Result<(), VpProtoError> {
    let presentation = sd_jwt_presentation();

    let encoded = encode_presentation_proto(&presentation)?;
    let decoded = decode_presentation_proto(&encoded)?;

    assert_eq!(decoded, presentation);
    Ok(())
}

#[test]
fn zk_presentation_round_trips_through_proto_json_and_brotli() -> Result<(), VpProtoError> {
    let presentation = zk_presentation();

    let json = presentation_to_proto_json(&presentation)?;
    let from_json = proto_json_to_presentation(&json)?;
    assert_eq!(from_json, presentation);

    let compressed = encode_presentation_proto_brotli(&presentation)?;
    let decompressed = decode_presentation_proto_brotli(&compressed)?;
    assert_eq!(decompressed, presentation);
    Ok(())
}

#[test]
fn invalid_hash_length_is_rejected() -> Result<(), VpProtoError> {
    let mut proto =
        reallyme_ssi_proto_codec::presentation::presentation_to_proto(&sd_jwt_presentation());
    if let Some(
        reallyme_ssi_proto::generated::proto::identity::presentation::v1::__buffa::oneof::presentation::Kind::SdJwtVc(model),
    ) = proto.kind.as_mut()
    {
        model.envelope_hash = Some(vec![1, 2, 3]);
    } else {
        return Err(VpProtoError::MissingField);
    }

    let error = match proto_to_presentation(&proto) {
        Ok(_) => return Err(VpProtoError::InvalidBytesLen),
        Err(error) => error,
    };

    assert_eq!(error, VpProtoError::InvalidBytesLen);
    Ok(())
}

#[test]
fn missing_suite_or_invalid_artifact_digest_fails_closed() -> Result<(), VpProtoError> {
    let mut proto =
        reallyme_ssi_proto_codec::presentation::presentation_to_proto(&zk_presentation());
    let Some(
        reallyme_ssi_proto::generated::proto::identity::presentation::v1::__buffa::oneof::presentation::Kind::Zk(model),
    ) = proto.kind.as_mut()
    else {
        return Err(VpProtoError::MissingField);
    };
    let Some(proof) = model.zk_proof.as_option_mut() else {
        return Err(VpProtoError::MissingField);
    };
    proof.proof_suite = Default::default();
    assert_eq!(
        proto_to_presentation(&proto),
        Err(VpProtoError::InvalidEnumValue)
    );

    let mut proto =
        reallyme_ssi_proto_codec::presentation::presentation_to_proto(&zk_presentation());
    let Some(
        reallyme_ssi_proto::generated::proto::identity::presentation::v1::__buffa::oneof::presentation::Kind::Zk(model),
    ) = proto.kind.as_mut()
    else {
        return Err(VpProtoError::MissingField);
    };
    let Some(proof) = model.zk_proof.as_option_mut() else {
        return Err(VpProtoError::MissingField);
    };
    proof.artifact_manifest_sha256 = vec![1_u8; 31];
    assert_eq!(
        proto_to_presentation(&proto),
        Err(VpProtoError::InvalidBytesLen)
    );
    Ok(())
}

#[test]
fn oversized_proto_is_rejected_before_decode() {
    let oversized = vec![0_u8; MAX_PRESENTATION_PROTO_MESSAGE_BYTES + 1];

    let result = decode_proto(&oversized);

    assert_eq!(result, Err(VpProtoError::MessageTooLarge));
}

#[test]
fn oversized_mdoc_is_rejected_before_encode_clone() {
    let presentation = Presentation::Mdoc(Box::new(MdocPresentation {
        device_response: vec![0_u8; MAX_MDOC_DEVICE_RESPONSE_BYTES + 1],
        envelope_hash: None,
        doc_type: None,
    }));

    let result = encode_presentation_proto(&presentation);

    assert_eq!(result, Err(VpProtoError::MdocDeviceResponseTooLarge));
}

#[test]
fn oversized_generated_mdoc_is_rejected_at_model_conversion() {
    use reallyme_ssi_proto::generated::proto::identity::presentation::v1::__buffa::oneof::presentation;
    use reallyme_ssi_proto::generated::proto::identity::presentation::v1::{
        MdocPresentation as ProtoMdocPresentation, Presentation as ProtoPresentation,
    };

    let proto = ProtoPresentation {
        kind: Some(presentation::Kind::Mdoc(Box::new(ProtoMdocPresentation {
            device_response: vec![0_u8; MAX_MDOC_DEVICE_RESPONSE_BYTES + 1],
            ..ProtoMdocPresentation::default()
        }))),
        ..ProtoPresentation::default()
    };

    assert_eq!(
        proto_to_presentation(&proto),
        Err(VpProtoError::MdocDeviceResponseTooLarge)
    );
    assert_eq!(
        encode_proto(&proto),
        Err(VpProtoError::MdocDeviceResponseTooLarge)
    );
}

#[test]
fn oversized_proto_json_is_rejected_before_deserialization() {
    let oversized = " ".repeat(MAX_PRESENTATION_PROTO_JSON_BYTES + 1);

    let result = json_to_proto(&oversized);

    assert_eq!(result, Err(VpProtoError::JsonTooLarge));
}

#[test]
fn unknown_proto_fields_fail_closed() {
    // Field 99 is not present in Presentation. Rejecting it prevents silent
    // contract drift because the exact v1 contract has no legacy mode.
    let unknown_field = [0x98_u8, 0x06, 0x01];

    let result = decode_proto(&unknown_field);

    assert_eq!(result, Err(VpProtoError::Decode));
}

#[test]
fn decoded_proto_has_a_non_cloneable_zeroizing_owner() -> Result<(), VpProtoError> {
    assert_zeroize_on_drop::<reallyme_ssi_proto_codec::presentation::SensitivePresentationProto>();

    let encoded = encode_presentation_proto(&sd_jwt_presentation())?;
    let mut decoded = decode_proto(&encoded)?;
    decoded.zeroize();

    assert!(decoded.is_cleared());
    Ok(())
}
