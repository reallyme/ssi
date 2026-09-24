// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Tests for generated status protobuf bindings.

#![cfg(feature = "generated")]
#![allow(missing_docs)]

use buffa::{EnumValue, Message, MessageField};
use reallyme_ssi_proto::generated::proto::identity::credential::v1::{Algorithm, StatusPurpose};
use reallyme_ssi_proto::generated::proto::identity::status::v1::{StatusList, StatusListSignature};

#[test]
fn status_list_proto_round_trips_with_buffa() {
    let status = StatusList {
        issuer_did: "did:example:issuer".to_owned(),
        purpose: EnumValue::from(StatusPurpose::Revocation),
        encoded_list: vec![0b1010_0000],
        length: 8,
        list_id: vec![7; 32],
        signature: MessageField::some(StatusListSignature {
            alg: EnumValue::from(Algorithm::Ed25519),
            sig_bytes: vec![3; 64],
            ..StatusListSignature::default()
        }),
        ..StatusList::default()
    };

    let encoded = status.encode_to_vec();
    let decoded_result = StatusList::decode(&mut encoded.as_slice());
    assert!(decoded_result.is_ok());
    let decoded = match decoded_result {
        Ok(decoded) => decoded,
        Err(_) => return,
    };

    assert_eq!(decoded.issuer_did, "did:example:issuer");
    assert_eq!(decoded.length, 8);
    assert_eq!(decoded.list_id, vec![7; 32]);
}

#[test]
fn status_list_proto_rejects_truncated_buffa_message() {
    let malformed = [
        0x42, 0x02, // field 8, length-delimited Signature with two declared bytes
        0x08, // truncated nested message: varint tag is present without a value
    ];

    let decoded_result = StatusList::decode(&mut malformed.as_slice());

    assert!(decoded_result.is_err());
}

#[test]
fn status_list_debug_redacts_encoded_material() {
    const SENSITIVE_ISSUER: &str = "did:example:sensitive-issuer";

    let status = StatusList {
        issuer_did: SENSITIVE_ISSUER.to_owned(),
        encoded_list: vec![0xde, 0xad, 0xbe, 0xef],
        length: 32,
        list_id: vec![0xa5; 32],
        ..StatusList::default()
    };

    let debug_output = format!("{status:?}");

    assert!(debug_output.contains("[REDACTED]"));
    assert!(!debug_output.contains(SENSITIVE_ISSUER));
    assert!(!debug_output.contains("222"));
}
